import streamlit as st
import pandas as pd
import os
from datetime import datetime
import plotly.express as px
from fpdf import FPDF
import hashlib

# -------------- Configuration --------------
DATA_FILE = "project_data.xlsx"
USER_FILE = "users.csv"

# -------------- Helper Functions --------------
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def load_users():
    if os.path.exists(USER_FILE):
        df = pd.read_csv(USER_FILE)
    else:
        df = pd.DataFrame(columns=["username", "hashed_password", "role"])
        df.to_csv(USER_FILE, index=False)

    if df.empty:
        default_admin = {
            "username": "admin",
            "hashed_password": hash_password("admin"),
            "role": "manager"
        }
        df = pd.DataFrame([default_admin])
        df.to_csv(USER_FILE, index=False)
        st.warning("Default admin user created: Username: admin | Password: admin")
    return df

def save_users(df):
    df.to_csv(USER_FILE, index=False)

def add_user(username, password, role):
    users = load_users()
    if username in users['username'].values:
        st.warning("Username already exists.")
    else:
        new_user = pd.DataFrame([[username, hash_password(password), role]], columns=["username", "hashed_password", "role"])
        users = pd.concat([users, new_user], ignore_index=True)
        save_users(users)
        st.success("User added successfully.")

def authenticate(username, password):
    users = load_users()
    hashed = hash_password(password)
    user = users[(users['username'] == username) & (users['hashed_password'] == hashed)]
    if not user.empty:
        return user.iloc[0]['role']
    return None

def load_data():
    if os.path.exists(DATA_FILE):
        return pd.read_excel(DATA_FILE)
    else:
        return pd.DataFrame(columns=["Project Number", "Department", "Job Number", "Job Description", "Start Date", "End Date", "Progress", "Comments", "Baseline"])

def save_data(df):
    df.to_excel(DATA_FILE, index=False)

def generate_gantt_chart(df):
    if df.empty:
        st.info("No data to plot.")
        return
    df_sorted = df.sort_values("Start Date")
    fig = px.timeline(
        df_sorted,
        x_start="Start Date",
        x_end="End Date",
        y="Job Description",
        color="Progress",
        title="Project Gantt Chart"
    )
    fig.update_yaxes(autorange="reversed")
    st.plotly_chart(fig)

def generate_pdf_summary(df):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    pdf.cell(200, 10, txt="Project Summary Report", ln=True, align='C')
    pdf.ln(10)
    for index, row in df.iterrows():
        for col in df.columns:
            pdf.cell(200, 8, txt=f"{col}: {row[col]}", ln=True)
        pdf.ln(5)
    file_name = f"summary_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    pdf.output(file_name)
    with open(file_name, "rb") as f:
        st.download_button(label="Download PDF Summary", data=f, file_name=file_name, mime="application/pdf")

# -------------- Login Function --------------
def login():
    if "logged_in" not in st.session_state:
        st.session_state.logged_in = False
    if "role" not in st.session_state:
        st.session_state.role = None

    st.title("Login")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    if st.button("Login"):
        role = authenticate(username, password)
        if role:
            st.session_state.logged_in = True
            st.session_state.username = username
            st.session_state.role = role
            # Do NOT call st.experimental_rerun() here
            # Instead, set a flag to indicate login success
            st.session_state.login_success = True
        else:
            st.error("Invalid username or password")

    # After inputs, check if login succeeded, then rerun outside
    if st.session_state.get("login_success", False):
        del st.session_state["login_success"]
        st.experimental_rerun()
    else:
        st.stop()

# -------------- User Management --------------
def user_management():
    st.subheader("User Management")
    username = st.text_input("New Username")
    password = st.text_input("New Password", type="password")
    role = st.selectbox("Role", ["machinery", "steel", "painting", "manager"])
    if st.button("Add User"):
        add_user(username, password, role)
    users = load_users()
    st.dataframe(users)

# -------------- Main App --------------
def main():
    if not st.session_state.get("logged_in", False):
        login()
        return

    st.title("Ship Repair Project Tracker")
    user_role = st.session_state.role

    # Sidebar Navigation & Logout
    with st.sidebar:
        st.header("Navigation")
        options = ["Data Entry", "Charts & Reports"]
        if user_role == "manager":
           options.append("User Management")
        menu = st.radio("Go to", options)

        if st.button("Logout"):
            st.session_state.clear()
            st.experimental_rerun()
            return  # <--- add this return here!

    data = load_data()

    if menu == "Data Entry":
        st.subheader("Data Entry")
        project_number = st.text_input("Enter Project Number")
        job_options = data[data["Project Number"] == project_number]["Job Number"].unique().tolist()
        job_mode = st.radio("Do you want to:", ["Add New Job", "Edit Existing Job"])

        if job_mode == "Edit Existing Job" and job_options:
            selected_job = st.selectbox("Select Job Number", job_options)
            row = data[(data["Project Number"] == project_number) & (data["Job Number"] == selected_job)].iloc[0]
            dept = row["Department"]

            if user_role == dept or user_role == "manager":
                st.markdown("**Note:** Project Number, Department, and Job Number cannot be changed.")
                job_desc = st.text_input("Job Description", value=row["Job Description"])
                start_date = st.date_input("Start Date", value=row["Start Date"])
                end_date = st.date_input("End Date", value=row["End Date"])
                progress = st.slider("Progress (%)", min_value=0, max_value=100, value=int(row["Progress"]))
                comments = st.text_area("Comments", value=row["Comments"])

                if st.button("Update Job"):
                    data.loc[(data["Project Number"] == project_number) &
                             (data["Job Number"] == selected_job),
                             ["Job Description", "Start Date", "End Date", "Progress", "Comments"]] = \
                             [job_desc, pd.to_datetime(start_date), pd.to_datetime(end_date), progress, comments]
                    save_data(data)
                    st.success("Job updated successfully.")
            else:
                st.warning("You do not have permission to edit this job.")

        elif job_mode == "Add New Job":
            job_number = st.text_input("Job Number")
            job_desc = st.text_input("Job Description")
            start_date = st.date_input("Start Date")
            end_date = st.date_input("End Date")
            progress = st.slider("Progress (%)", min_value=0, max_value=100)
            comments = st.text_area("Comments")

            if st.button("Add Job"):
                new_entry = {
                    "Project Number": project_number,
                    "Department": user_role,
                    "Job Number": job_number,
                    "Job Description": job_desc,
                    "Start Date": pd.to_datetime(start_date),
                    "End Date": pd.to_datetime(end_date),
                    "Progress": progress,
                    "Comments": comments,
                    "Baseline": True if not ((data["Project Number"] == project_number) &
                                              (data["Job Number"] == job_number)).any() else False
                }
                data = pd.concat([data, pd.DataFrame([new_entry])], ignore_index=True)
                save_data(data)
                st.success("New job added successfully.")

    elif menu == "Charts & Reports":
        st.subheader("Charts & Reports")
        project_number = st.text_input("Enter Project Number to View Charts")
        filtered = data[data["Project Number"] == project_number]

        if not filtered.empty:
            st.dataframe(filtered)

            if st.button("Generate Gantt Chart"):
                generate_gantt_chart(filtered)

            if st.button("Generate PDF Summary"):
                generate_pdf_summary(filtered)

            excel_bytes = filtered.to_excel(index=False)
            st.download_button("Download Excel", data=excel_bytes, file_name="project_data.xlsx", mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")

    elif menu == "User Management" and user_role == "manager":
        user_management()

# -------------- Run App --------------
main()
