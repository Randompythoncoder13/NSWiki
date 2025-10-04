import streamlit as st
from sqlalchemy import create_engine, Column, Integer, String, Text, Boolean, ForeignKey, DateTime
from sqlalchemy.orm import sessionmaker, relationship, declarative_base
import hashlib
import datetime
import re
import urllib.parse
import secrets
from streamlit_cookies_controller import CookieController

# --- DATABASE SETUP (SQLAlchemy) ---
db_creds = st.secrets["connections"]["wiki_db"]

# Construct the database URL
db_url = (
    f"{db_creds['dialect']}://"
    f"{db_creds['username']}:{db_creds['password']}@"
    f"{db_creds['host']}:{db_creds['port']}/"
    f"{db_creds['database']}"
)

engine = create_engine(db_url)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


# --- DATABASE MODELS ---

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    is_admin = Column(Boolean, default=False)
    session_token = Column(String, unique=True, index=True, nullable=True)
    token_expiry = Column(DateTime, nullable=True)

    revisions = relationship("Revision", back_populates="author")

class Page(Base):
    __tablename__ = "pages"
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String, unique=True, index=True, nullable=False)
    current_revision_id = Column(Integer, ForeignKey("revisions.id", name="fk_current_revision"), nullable=True)
    current_revision = relationship("Revision", foreign_keys=[current_revision_id])
    revisions = relationship("Revision", foreign_keys="[Revision.page_id]", back_populates="page", cascade="all, delete-orphan")

class Revision(Base):
    __tablename__ = "revisions"
    id = Column(Integer, primary_key=True, index=True)
    content = Column(Text, nullable=False)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)
    status = Column(String, default="pending")
    page_id = Column(Integer, ForeignKey("pages.id"), nullable=False)
    page = relationship("Page", foreign_keys=[page_id], back_populates="revisions")
    author_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    author = relationship("User", back_populates="revisions")

Base.metadata.create_all(bind=engine)


# --- UTILITY FUNCTIONS ---

def get_db():
    """Returns a new database session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()


def verify_password(user_password, hashed_password):
    return hashed_password == hash_password(user_password)


def get_user(db, username: str):
    return db.query(User).filter(User.username == username).first()


def get_page_by_title(db, title: str):
    return db.query(Page).filter(Page.title == title).first()


def get_approved_content(page):
    if page and page.current_revision:
        return page.current_revision.content
    return "*This page has not been published yet. An admin needs to approve the first revision.*"


def parse_wiki_links(content, all_page_titles):
    def replace_link(match):
        title = match.group(1)
        actual_title = next((p for p in all_page_titles if p.lower() == title.lower()), None)
        if actual_title:
            url_encoded_title = urllib.parse.quote(actual_title)
            return f'<a href="?page={url_encoded_title}" target="_self">{actual_title}</a>'
        else:
            url_encoded_title = urllib.parse.quote(title)
            return f'<a href="?action=create&title={url_encoded_title}" target="_self" style="color:red;">{title}</a>'

    return re.sub(r"\[\[(.*?)]]", replace_link, content)


# --- AUTHENTICATION & SESSION LOGIC ---

def initialize_session(cookies: CookieController):
    """Initializes session state and attempts to log in from a cookie."""
    # This part runs only on the very first run of a new session
    if 'logged_in' not in st.session_state:
        st.session_state.logged_in = False
        st.session_state.username = ""
        st.session_state.is_admin = False
        st.session_state.page = "Mitteleuropa Wiki"
        st.session_state.action = "view"

    # This part runs on every script run if the user isn't logged in.
    # It attempts to authenticate using a cookie.
    if not st.session_state.logged_in:
        token = cookies.get('session_token')
        if token:
            db = next(get_db())
            user = db.query(User).filter(User.session_token == token).first()
            if user and user.token_expiry and user.token_expiry > datetime.datetime.utcnow():
                st.session_state.logged_in = True
                st.session_state.username = user.username
                st.session_state.is_admin = user.is_admin
                # Rerun to ensure the page reflects the logged-in state immediately
                st.rerun()


def handle_logout(cookies: CookieController):
    """Clears session state, database token, and cookie."""
    token = cookies.get('session_token')
    if token:
        db = next(get_db())
        user = db.query(User).filter(User.session_token == token).first()
        if user:
            user.session_token = None
            user.token_expiry = None
            db.commit()
    cookies.remove('session_token')
    for key in list(st.session_state.keys()):
        del st.session_state[key]
    st.rerun()


# --- STREAMLIT APP ---

def main():
    st.set_page_config(page_title="Mitteleuropa Wiki", layout="wide")

    cookies = CookieController(key="wiki_cookie_manager")
    initialize_session(cookies)

    # --- Capture navigation from URL parameters ---
    # This must run after initialize_session and before the rest of the app.
    # It captures the user's intent from the URL.
    query_params = st.query_params
    if "page" in query_params:
        st.session_state.page = query_params.get("page")
        st.session_state.action = "view"
        del st.query_params["page"]  # Use 'del' to remove the parameter
    elif query_params.get("action") == "create":
        st.session_state.action = "create"
        if "title" in query_params:
            st.session_state.prefill_title = query_params.get("title")
            del st.query_params["title"]
        del st.query_params["action"]


    st.title("📚 Mitteleuropa Wiki")
    db_session = next(get_db())

    # --- SIDEBAR ---
    with st.sidebar:
        st.header("Navigation")
        if not st.session_state.logged_in:
            login_tab, register_tab = st.tabs(["Login", "Register"])
            with login_tab:
                with st.form("login_form"):
                    username = st.text_input("Username")
                    password = st.text_input("Password", type="password")
                    if st.form_submit_button("Login"):
                        user = get_user(db_session, username)
                        if user and verify_password(password, user.hashed_password):
                            token = secrets.token_hex(16)
                            expiry = datetime.datetime.utcnow() + datetime.timedelta(days=7)
                            user.session_token = token
                            user.token_expiry = expiry
                            db_session.commit()
                            cookies.set('session_token', token, expires=expiry)

                            st.session_state.logged_in = True
                            st.session_state.username = user.username
                            st.session_state.is_admin = user.is_admin
                            st.success("Logged in successfully!")
                            st.rerun()
                        else:
                            st.error("Invalid username or password")
            with register_tab:
                with st.form("register_form"):
                    new_username = st.text_input("Choose a Username")
                    new_password = st.text_input("Choose a Password", type="password")
                    if st.form_submit_button("Register"):
                        if get_user(db_session, new_username):
                            st.error("Username already exists.")
                        elif not new_username or not new_password:
                            st.error("Username and password cannot be empty.")
                        else:
                            is_first_user = db_session.query(User).count() == 0
                            hashed_pw = hash_password(new_password)
                            new_user = User(username=new_username, hashed_password=hashed_pw, is_admin=is_first_user)
                            db_session.add(new_user)
                            db_session.commit()
                            st.success(f"Account created for {new_username}. Please login.")
                            if is_first_user:
                                st.info("✨ You are the first user! You have been granted admin privileges.")
                            st.rerun()
        else:  # Logged in
            st.write(f"Welcome, **{st.session_state.username}**!")
            if st.session_state.is_admin: st.markdown("`Admin`")
            if st.button("Logout"): handle_logout(cookies)
            st.divider()
            if st.button("➕ Create New Page"):
                st.session_state.action = "create"
                st.rerun()
            if st.session_state.is_admin and st.button("🛡️ Admin Panel"):
                st.session_state.action = "admin_panel"
                st.rerun()
            st.divider()
            st.subheader("All Pages")
            pages = db_session.query(Page).order_by(Page.title).all()
            for page in pages:
                if st.button(page.title, key=f"page_{page.id}", use_container_width=True):
                    st.session_state.page = page.title
                    st.session_state.action = "view"
                    st.rerun()

    # --- MAIN CONTENT AREA ---
    if not st.session_state.logged_in:
        st.info("Please log in or register using the sidebar to view and edit pages.")
        return

    if st.session_state.action == "admin_panel" and st.session_state.is_admin:
        st.header("Admin Panel: Pending Revisions")
        pending_revisions = db_session.query(Revision).filter(Revision.status == "pending").all()
        if not pending_revisions:
            st.success("No pending revisions to review. All clear! ✅")
        else:
            for rev in pending_revisions:
                with st.expander(
                        f"**{rev.page.title}** by *{rev.author.username}* at {rev.timestamp.strftime('%Y-%m-%d %H:%M')} UTC"):
                    st.subheader("Proposed Content")
                    st.markdown(rev.content, unsafe_allow_html=True)
                    st.subheader("Currently Approved Content")
                    st.markdown(f"```markdown\n{get_approved_content(rev.page)}\n```")
                    col1, col2 = st.columns(2)
                    if col1.button("Approve", key=f"approve_{rev.id}", type="primary"):
                        rev.status = "approved"
                        rev.page.current_revision_id = rev.id
                        db_session.commit()
                        st.success("Revision approved.")
                        st.rerun()
                    if col2.button("Reject", key=f"reject_{rev.id}"):
                        rev.status = "rejected"
                        db_session.commit()
                        st.warning("Revision rejected.")
                        st.rerun()
    elif st.session_state.action == "create":
        st.header("Create a New Wiki Page")
        prefill_title = st.session_state.pop('prefill_title', '')
        with st.form("create_page_form"):
            new_title = st.text_input("Page Title", value=prefill_title)
            new_content = st.text_area("Page Content", height=400, help="Link with [[Page Title]].")
            if st.form_submit_button("Create Page"):
                if not new_title or not new_content:
                    st.error("Title and content are required.")
                elif get_page_by_title(db_session, new_title):
                    st.error("Page already exists.")
                else:
                    user = get_user(db_session, st.session_state.username)
                    new_page = Page(title=new_title)
                    db_session.add(new_page)
                    db_session.flush()
                    db_session.add(
                        Revision(content=new_content, page_id=new_page.id, author_id=user.id, status="pending"))
                    db_session.commit()
                    st.success(f"Page '{new_title}' submitted for review.")
                    st.session_state.page = new_title
                    st.session_state.action = "view"
                    st.rerun()
    elif st.session_state.action == "edit":
        page = get_page_by_title(db_session, st.session_state.get('page', ''))
        if not page:
            st.error("Page not found.")
            st.session_state.action = "view"
            st.session_state.page = "main"
            st.rerun()
        else:
            st.header(f"Editing: {page.title}")
            with st.form("edit_page_form"):
                edited_content = st.text_area("Page Content", value=get_approved_content(page), height=500)
                if st.form_submit_button("Submit for Review"):
                    user = get_user(db_session, st.session_state.username)
                    db_session.add(
                        Revision(content=edited_content, page_id=page.id, author_id=user.id, status="pending"))
                    db_session.commit()
                    st.success("Edit submitted for approval.")
                    st.session_state.action = "view"
                    st.rerun()
            if st.button("Cancel Edit"): st.session_state.action = "view"; st.rerun()
    else:  # View Page
        page_title = st.session_state.get('page', 'main')
        page = get_page_by_title(db_session, page_title)
        if not page:
            st.header(f"Welcome to the Wiki!")
            st.write(f"The page '{page_title}' does not exist yet.")
            if st.button(f"Create the '{page_title}' page"):
                st.session_state.action = "create"
                st.session_state.prefill_title = page_title
                st.rerun()
        else:
            main_col, info_col = st.columns([3, 1])
            with main_col:
                st.header(page.title)
                if st.button("✏️ Edit this Page"): st.session_state.action = "edit"; st.rerun()
                st.markdown("---")
                all_pages = [p.title for p in db_session.query(Page.title).all()]
                st.markdown(parse_wiki_links(get_approved_content(page), all_pages), unsafe_allow_html=True)
            with info_col:
                with st.container(border=True):
                    st.subheader("Page Info")
                    st.markdown("---")
                    if page.current_revision:
                        st.caption("Last approved edit by:")
                        st.markdown(f"**{page.current_revision.author.username}**")
                        st.caption("Approved on:")
                        st.markdown(f"**{page.current_revision.timestamp.strftime('%Y-%m-%d %H:%M')}** UTC")
                    else:
                        st.info("This page is awaiting its first review.")


if __name__ == "__main__":
    main()
