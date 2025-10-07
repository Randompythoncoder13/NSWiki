import streamlit as st
from sqlalchemy import create_engine, Column, Integer, String, Text, Boolean, ForeignKey, DateTime
from sqlalchemy.orm import relationship, declarative_base, Session
import hashlib
import datetime
import re
import urllib.parse
import secrets
from streamlit_cookies_controller import CookieController

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


@st.cache_resource
def get_engine():
    """Creates a SQLAlchemy engine and caches it."""
    db_creds = st.secrets["connections"]["wiki_db"]
    db_url = (
        f"{db_creds['dialect']}://"
        f"{db_creds['username']}:{db_creds['password']}@"
        f"{db_creds['host']}:{db_creds['port']}/"
        f"{db_creds['database']}"
    )
    engine = create_engine(db_url)
    Base.metadata.create_all(bind=engine) # Create tables if they don't exist
    return engine

@st.cache_resource
def get_db_sessionmaker():
    """Creates a SQLAlchemy sessionmaker and caches it."""
    engine = get_engine()
    return Session(autocommit=False, autoflush=False, bind=engine)


# --- UTILITY FUNCTIONS ---

def get_db_session():
    """Returns a new database session."""
    db = get_db_sessionmaker()
    return db


def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()


def verify_password(user_password, hashed_password):
    return hashed_password == hash_password(user_password)


def get_user(db, username: str):
    return db.query(User).filter(User.username == username).first()


@st.cache_data(ttl=60) # Cache for 60 seconds
def get_all_page_titles(_db_session_maker): # Pass in a dummy arg to help with cache invalidation if needed
    """Gets a list of all page titles. Cached to prevent frequent queries."""
    with get_db_session() as db:
        return [p.title for p in db.query(Page.title).order_by(Page.title).all()]

@st.cache_data(ttl=30)
def get_page_by_title_cached(title: str):
    """Gets a full page object by its title. Cached."""
    if not title: return None
    with get_db_session() as db:
        page = db.query(Page).filter(Page.title == title).first()
        if page:
            # Eagerly load related data to prevent issues with closed sessions
            if page.current_revision:
                # page.current_revision.content
                # page.current_revision.author.username
                pass
        return page


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
    if 'logged_in' not in st.session_state:
        st.session_state.logged_in = False
        st.session_state.username = ""
        st.session_state.is_admin = False
        st.session_state.page = "Mitteleuropa Wiki"
        st.session_state.action = "view"

    if not st.session_state.logged_in:
        token = cookies.get('session_token')
        if token:
            with get_db_session() as db:
                user = db.query(User).filter(User.session_token == token).first()
                if user and user.token_expiry and user.token_expiry > datetime.datetime.utcnow():
                    st.session_state.logged_in = True
                    st.session_state.username = user.username
                    st.session_state.is_admin = user.is_admin
                    st.rerun()


def handle_logout(cookies: CookieController):
    """Callback to handle user logout."""
    token = cookies.get('session_token')
    if token:
        with get_db_session() as db:
            user = db.query(User).filter(User.session_token == token).first()
            if user:
                user.session_token = None
                user.token_expiry = None
                db.commit()
    cookies.remove('session_token')
    # Reset all session state keys
    for key in list(st.session_state.keys()):
        del st.session_state[key]
    # No st.rerun() needed here, Streamlit does it automatically after a callback


def set_action(action: str, title: str = None):
    """Callback to change the current action in the session state."""
    st.session_state.action = action
    if title:
        st.session_state.page = title


def draw_sidebar(db, cookies, all_page_titles):
    with st.sidebar:
        st.header("Navigation")
        if not st.session_state.logged_in:
            # Login/Register Forms
            login_tab, register_tab = st.tabs(["Login", "Register"])
            with login_tab:
                with st.form("login_form"):
                    username = st.text_input("Username")
                    password = st.text_input("Password", type="password")
                    if st.form_submit_button("Login"):
                        user = get_user(db, username)
                        if user and verify_password(password, user.hashed_password):
                            token = secrets.token_hex(16)
                            expiry = datetime.datetime.utcnow() + datetime.timedelta(days=7)
                            user.session_token = token
                            user.token_expiry = expiry
                            db.commit()
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
                        if get_user(db, new_username):
                            st.error("Username already exists.")
                        elif not new_username or not new_password:
                            st.error("Username and password cannot be empty.")
                        else:
                            is_first_user = db.query(User).count() == 0
                            new_user = User(username=new_username, hashed_password=hash_password(new_password),
                                            is_admin=is_first_user)
                            db.add(new_user)
                            db.commit()
                            st.success(f"Account created for {new_username}. Please login.")
                            if is_first_user: st.info(
                                "✨ You are the first user! You have been granted admin privileges.")
                            st.rerun()
        else:  # Logged in
            st.write(f"Welcome, **{st.session_state.username}**!")
            if st.session_state.is_admin: st.markdown("`Admin`")
            st.button("Logout", on_click=handle_logout, args=(cookies,))
            st.divider()
            st.button("➕ Create New Page", on_click=set_action, args=("create",))
            if st.session_state.is_admin:
                st.button("🛡️ Admin Panel", on_click=set_action, args=("admin_panel",))
            st.divider()
            st.subheader("All Pages")
            for title in all_page_titles:
                st.button(title, key=f"page_{title}", use_container_width=True, on_click=set_action,
                          args=("view", title))


def draw_admin_panel(db):
    st.header("Admin Panel: Pending Revisions")
    pending_revisions = db.query(Revision).filter(Revision.status == "pending").all()
    if not pending_revisions:
        st.success("No pending revisions to review. All clear! ✅")
    else:
        for rev in pending_revisions:
            with st.expander(
                    f"**{rev.page.title}** by *{rev.author.username}* at {rev.timestamp.strftime('%Y-%m-%d %H:%M')} UTC"):
                st.subheader("Proposed Content")
                st.markdown(rev.content, unsafe_allow_html=True)
                # We need the full page object to get approved content
                page_for_rev = get_page_by_title_cached(rev.page.title)
                st.subheader("Currently Approved Content")
                st.markdown(f"```markdown\n{get_approved_content(page_for_rev)}\n```")
                col1, col2 = st.columns(2)
                if col1.button("Approve", key=f"approve_{rev.id}", type="primary"):
                    rev.status = "approved"
                    rev.page.current_revision_id = rev.id
                    db.commit()
                    # Clear caches that depend on page content
                    get_page_by_title_cached.clear()
                    get_all_page_titles.clear()
                    st.success("Revision approved.")
                    st.rerun()
                if col2.button("Reject", key=f"reject_{rev.id}"):
                    rev.status = "rejected"
                    db.commit()
                    st.warning("Revision rejected.")
                    st.rerun()


def draw_create_page(db):
    st.header("Create a New Wiki Page")
    prefill_title = st.session_state.pop('prefill_title', '')
    with st.form("create_page_form"):
        new_title = st.text_input("Page Title", value=prefill_title)
        new_content = st.text_area("Page Content", height=400, help="Link with [[Page Title]].")
        if st.form_submit_button("Create Page"):
            if not new_title or not new_content:
                st.error("Title and content are required.")
            elif get_page_by_title_cached(new_title):
                st.error("Page already exists.")
            else:
                user = get_user(db, st.session_state.username)
                new_page = Page(title=new_title)
                db.add(new_page)
                db.flush()  # Flush to get the new_page.id
                db.add(Revision(content=new_content, page_id=new_page.id, author_id=user.id, status="pending"))
                db.commit()
                # Clear the page list cache since we added a new one
                get_all_page_titles.clear()
                st.success(f"Page '{new_title}' submitted for review.")
                set_action("view", new_title)
                st.rerun()


def draw_edit_page(db, page):
    st.header(f"Editing: {page.title}")
    with st.form("edit_page_form"):
        edited_content = st.text_area("Page Content", value=get_approved_content(page), height=500)
        if st.form_submit_button("Submit for Review"):
            user = get_user(db, st.session_state.username)
            db.add(Revision(content=edited_content, page_id=page.id, author_id=user.id, status="pending"))
            db.commit()
            st.success("Edit submitted for approval.")
            set_action("view", page.title)
            st.rerun()
    st.button("Cancel Edit", on_click=set_action, args=("view", page.title))


def draw_view_page(all_page_titles):
    """
    Draws the main page view. This version is corrected to prevent
    state management bugs that can cause double rendering.
    """

    # Callback to cleanly set the action and pre-fill the title for creation
    def go_to_create_page(title_to_create):
        st.session_state.action = "create"
        st.session_state.prefill_title = title_to_create

    page_title = st.session_state.get('page', 'Mitteleuropa Wiki')
    page = get_page_by_title_cached(page_title)

    if not page:
        st.header(f"Welcome to the Wiki!")
        st.write(f"The page '{page_title}' does not exist yet.")

        # OPTIMIZATION: Use a dedicated callback to handle the state change.
        # This is much cleaner and avoids the bugs caused by using kwargs and
        # a separate `if` block with st.rerun().
        st.button(
            f"Create the '{page_title}' page",
            on_click=go_to_create_page,
            args=(page_title,)  # Pass the page_title to the callback
        )
    else:
        main_col, info_col = st.columns([3, 1])
        with main_col:
            st.header(page.title)
            st.button("✏️ Edit this Page", on_click=set_action, args=("edit", page.title))
            st.markdown("---")
            content = get_approved_content(page)
            st.markdown(parse_wiki_links(content, all_page_titles), unsafe_allow_html=True)
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


# --- MAIN APP ---
def main():
    st.set_page_config(page_title="Mitteleuropa Wiki", layout="wide")
    cookies = CookieController(key="wiki_cookie_manager")
    initialize_session(cookies)

    # --- OPTIMIZATION 4: CENTRALIZED URL PARAMETER HANDLING ---
    query_params = st.query_params
    if "page" in query_params:
        st.session_state.page = query_params.get("page")
        st.session_state.action = "view"
        st.query_params.clear()  # Clear all params after processing
    elif query_params.get("action") == "create" and "title" in query_params:
        st.session_state.action = "create"
        st.session_state.prefill_title = query_params.get("title")
        st.query_params.clear()

    st.title("📚 Mitteleuropa Wiki")

    # --- OPTIMIZATION 5: ONE DATABASE SESSION PER SCRIPT RUN ---
    # We now get a single session and pass it to the functions that need it.
    # This is more efficient than opening and closing sessions multiple times.
    with get_db_session() as db:

        # --- OPTIMIZATION 6: FETCH DATA ONCE, USE MANY TIMES ---
        # Fetch the list of all page titles once and pass it where needed.
        # Thanks to @st.cache_data, this will only hit the DB every 60 seconds.
        all_page_titles = get_all_page_titles(get_db_sessionmaker())

        draw_sidebar(db, cookies, all_page_titles)

        # Main content area router
        if not st.session_state.logged_in:
            st.info("Please log in or register using the sidebar to view and edit pages.")
            return

        action = st.session_state.get("action", "view")

        if action == "admin_panel" and st.session_state.is_admin:
            draw_admin_panel(db)
        elif action == "create":
            draw_create_page(db)
        elif action == "edit":
            page_to_edit = get_page_by_title_cached(st.session_state.get('page'))
            if page_to_edit:
                draw_edit_page(db, page_to_edit)
            else:
                st.error("Page not found to edit.")
                set_action("view", "Mitteleuropa Wiki")
                st.rerun()
        else:  # "view" is the default
            draw_view_page(all_page_titles)


if __name__ == "__main__":
    main()
