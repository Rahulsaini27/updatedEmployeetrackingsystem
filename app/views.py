from django.shortcuts import render, get_object_or_404, redirect
from django.http import HttpResponseRedirect
from django.conf import settings
from django.contrib import messages
from django.core.mail import send_mail
from django.http import HttpResponse, JsonResponse

import math
import random
from passwordgenerator import pwgenerator # Assuming this is installed
import uuid
import datetime
import json
import functools

from fuzzywuzzy import fuzz # Assuming fuzzywuzzy is installed
from fuzzywuzzy import process # Assuming fuzzywuzzy is installed

import plotly.express as px
from plotly.offline import plot
import plotly.graph_objs as go
import pandas as pd # Assuming pandas is installed

# Import your new decorators
from .decorators import permission_required, privileged_access_required

# Import all models
from .models import AttendanceLogs, Board, Role, Permission, Employee, Meeting, Monitoring, MonitoringDetails, Organization, OrganizationNews, PowerMonitoring, Project, Project_Employee_Linker, ScreenShotsMonitoring, Task, WorkProductivityDataset, Leaves


password = pwgenerator.generate()
# Create your views here.
import secrets
import string

def generate_password(length=10):
    characters = string.ascii_letters + string.digits  # + string.punctuation (optional)
    return ''.join(secrets.choice(characters) for _ in range(length))

def generateOTP():
    digits = "0123456789"
    OTP = ""
    for i in range(5):
        OTP += digits[math.floor(random.random() * 10)]
    return OTP

def error_404_view(request, exception):
    return render(request,'404.html')

def error_500_view(request, exception):
    return render(request,'500.html')

# These login_required decorators handle authentication and user type.
# They are kept for specific pages that are strictly type-gated,
# not for views protected by the new RBAC system.
def org_login_required(function):
    @functools.wraps(function)
    def wrapper(request, *args, **kw):
        if 'logged_in' in request.session:
            if request.session['u_type'] == 'org':
                return function(request, *args, **kw)
            else:
                messages.error(request, "You don't have privilege to access this page!")
                return HttpResponseRedirect('/')
        else:
            messages.error(request, "Logout Request/ Unauthorized Request, Please login!")
            return HttpResponseRedirect('/LoginOrg')
    return wrapper

def user_login_required(function):
    @functools.wraps(function)
    def wrapper(request, *args, **kw):
        if 'logged_in' in request.session:
            if request.session['u_type'] == 'emp':
                return function(request, *args, **kw)
            else:
                messages.error(request, "You don't have privilege to access this page!")
                return HttpResponseRedirect('/')
        else:
            messages.error(request, "Logout Request / Unauthorized Request, Please login!")
            return HttpResponseRedirect('/LoginUser')
    return wrapper

def index(request):
    return render(request, 'index.html')

def faq(request):
    return render(request, 'faq.html')

def contact(request):
    if request.method == 'POST':
        cname = request.POST['cname']
        cemail = request.POST['cemail']
        cquery = request.POST['cquery']
        subject = 'MyRemoteDesk - New Enquiry'
        message = f'Name : {cname}, Email : {cemail}, Query : {cquery}'
        email_from = settings.EMAIL_HOST_USER
        recipient_list = ["narender.rk10@gmail.com",
                          "2021.narender.keswani@ves.ac.in",
                          "2021.prathamesh.bhosale@ves.ac.in",
                          "2021.chinmay.vyapari@ves.ac.in"]
        send_mail(subject, message, email_from, recipient_list)
        send_mail(subject, "YOUR QUERY WILL BE PROCESSED! WITHIN 24 HOURS", email_from, [cemail])
        messages.success(request, "Your Query has been recorded.")
        msg = "Your Query has been recorded."
        return render(request, 'contact.html', {"msg" : msg})
    return render(request, 'contact.html')

def org_login(request):
    if request.method == "POST":
        o_email = request.POST['o_email']
        o_pass = request.POST['o_pass']
        org_details = Organization.objects.filter(o_email=o_email, o_password=o_pass).values()
        if org_details:
            request.session['logged_in'] = True
            request.session['o_email'] = org_details[0]["o_email"]
            request.session['o_id'] = org_details[0]["id"]
            request.session['o_name'] = org_details[0]["o_name"]
            request.session['u_type'] = "org"
            return HttpResponseRedirect('/org_index')
        else:
            return render(request, 'OrgLogin.html', {'details': "0"})
    else:
        return render(request, 'OrgLogin.html')

def user_login(request):
    if request.method == "POST":
        e_email = request.POST['e_email']
        e_pass = request.POST['e_pass']
        user_details = Employee.objects.filter(e_email=e_email, e_password=e_pass).values()
        if user_details:
            request.session['logged_in'] = True
            request.session['u_email'] = user_details[0]["e_email"]
            request.session['u_id'] = user_details[0]["id"]
            request.session['u_name'] = user_details[0]["e_name"]
            request.session['u_oid'] = user_details[0]["o_id_id"]
            request.session['u_type'] = "emp"
            return HttpResponseRedirect('/user_index')
        else:
            return render(request, 'EmpLogin.html', {'msg': "0"})
    else:
        return render(request, 'EmpLogin.html')


def org_register(request):
    if request.method == "POST":
        o_name = request.POST['org_name']
        o_email = request.POST['o_email']
        password1 = request.POST['password1']
        password2 = request.POST['password2']
        contact_no = request.POST['contact_no']
        website = request.POST['website']
        o_address = request.POST['o_address']
        if password1 == password2:
            otp = generateOTP()
            request.session['tempOTP'] = otp
            subject = 'MyRemoteDesk - OTP Verification'
            message = f'Hi {o_name}, thank you for registering in MyRemoteDesk . Your One Time Password (OTP) for verfication is {otp}'
            email_from = settings.EMAIL_HOST_USER
            recipient_list = [o_email, ]
            send_mail(subject, message, email_from, recipient_list)
            request.session['tempOrg_name'] = o_name
            request.session['tempOrg_email'] = o_email
            request.session['tempPassword'] = password2
            request.session['tempContact_no'] = contact_no
            request.session['tempWebsite'] = website
            request.session['tempO_address'] = o_address
            return HttpResponseRedirect('/VerifyEmail')
        else:
            messages.error("Password not matched!")
    else:
        return render(request, 'OrgRegister.html')

def verifyEmail(request):
    if request.method == 'POST':
        theOTP = request.POST['eotp']
        mOTP = request.session['tempOTP']
        if(theOTP == mOTP):
            myDB_o_name = request.session['tempOrg_name']
            myDB_o_email = request.session['tempOrg_email']
            myDB_password = request.session['tempPassword']
            myDB_contact_no = request.session['tempContact_no']
            myDB_website = request.session['tempWebsite']
            myDB_o_address = request.session['tempO_address']
            try:
                obj = Organization.objects.create(o_name=myDB_o_name, o_email=myDB_o_email, o_password=myDB_password, o_contact=myDB_contact_no, o_website=myDB_website, o_address=myDB_o_address)
                obj.save()
                for key in list(request.session.keys()):
                    del request.session[key]
                messages.success(request,"You are successfully registered")
                return HttpResponseRedirect('/LoginOrg')
            except Exception: # Catch broader exceptions during creation
                for key in list(request.session.keys()):
                    del request.session[key]
                messages.error(request,"Error was occurred!")
                return render(request, 'OrgLogin.html', {'details': "Error Occurred"})
        else:
            messages.error(request, 'OTP is not matched!')
    else:
        return render(request,'verifyOTP.html')

@org_login_required
def org_index(request):
    return render(request,'OrgIndex.html')

@user_login_required
def user_index(request):
    return render(request,'EmpIndex.html')

@privileged_access_required
@permission_required('change_password')
def org_change_password(request):
    # Use request.custom_user for current user details
    current_org_id = request.custom_user.id
    o_email = request.custom_user.o_email

    if request.method == 'POST':
        oldPwd = request.POST['oldPwd']
        newPwd = request.POST['newPwd']
        org_obj = Organization.objects.filter(o_email=o_email, o_password=oldPwd, pk=current_org_id).first()
        if org_obj:
            org_obj.o_password = newPwd
            org_obj.save()
            subject = 'MyRemoteDesk - Password Changed'
            message = f'Hi, your password was changed successfully! From MyRemoteDesk'
            email_from = settings.EMAIL_HOST_USER
            recipient_list = [o_email, ]
            send_mail(subject, message, email_from, recipient_list)
            messages.success(request, "Password Change Successfully")
            return HttpResponseRedirect('/org_change_password')
        else:
            subject = 'MyRemoteDesk - Notifications'
            message = f'Hi, there was attempt to change your password! From MyRemoteDesk'
            email_from = settings.EMAIL_HOST_USER
            recipient_list = [o_email, ]
            send_mail(subject, message, email_from, recipient_list)
            messages.error(request, "Old Password was not matched!")
            return HttpResponseRedirect('/org_change_password')
    else:
        return render(request, 'OrgChangePass.html')

@privileged_access_required
@permission_required('change_password')
def user_change_password(request):
    # Use request.custom_user for current user details
    current_emp_id = request.custom_user.id
    current_org_id = request.custom_user.o_id_id # Employee's associated organization ID
    u_email = request.custom_user.e_email

    if request.method == 'POST':
        oldPwd = request.POST['oldPwd']
        newPwd = request.POST['newPwd']
        emp_obj = Employee.objects.filter(e_email=u_email, e_password=oldPwd, pk=current_emp_id, o_id_id=current_org_id).first()
        if emp_obj:
            emp_obj.e_password = newPwd
            emp_obj.save()
            subject = 'MyRemoteDesk - Password Changed'
            message = f'Hi, your password was changed successfully! From MyRemoteDesk'
            email_from = settings.EMAIL_HOST_USER
            recipient_list = [u_email, ]
            send_mail(subject, message, email_from, recipient_list)
            messages.success(request,"Password Change Successfully")
            return HttpResponseRedirect('/user_change_password')
        else:
            subject = 'MyRemoteDesk - Notifications'
            message = f'Hi, there was attempt to change your password! From MyRemoteDesk'
            email_from = settings.EMAIL_HOST_USER
            recipient_list = [u_email, ]
            send_mail(subject, message, email_from, recipient_list)
            messages.error(request, "Old Password was not matched!")
            return HttpResponseRedirect('/user_change_password')
    else:
        return render(request, 'EmpChangePass.html')

def org_forgot_password(request):
    if request.method == 'POST':
        o_email = request.POST['o_email']
        request.session['tempfpOrgEmail'] = o_email
        org_details = Organization.objects.filter(o_email=o_email).values()
        if org_details:
            otp = generateOTP()
            request.session['tempfpOrgOTP'] = otp
            subject = 'MyRemoteDesk - OTP Verification for Forgot Password'
            message = f'Hi {o_email}, Your One Time Password (OTP) for forgot password is {otp}'
            email_from = settings.EMAIL_HOST_USER
            recipient_list = [o_email, ]
            send_mail(subject, message, email_from, recipient_list)
            return HttpResponseRedirect('/org-forgot-password-otp-verify')
        else:
            return render(request, 'Org_fp.html', {'msg': "0"})
    else:
        return render(request, 'Org_fp.html')

def org_forgot_password_otp_verify(request):
    if request.method == 'POST':
        fp_org_otp = request.POST['fp_org_otp']
        tempOrgFpOTP = request.session['tempfpOrgOTP']
        if(fp_org_otp == tempOrgFpOTP):
            return HttpResponseRedirect('/org-forgot-password-change-pass')
        else:
            return render(request, 'OrgFpVerifyOTP.html', {'msg': "0"})
    else:
        return render(request, 'OrgFpVerifyOTP.html')

def org_forgot_password_change_password(request):
    if request.method == 'POST':
        tempOrgFpEmail = request.session['tempfpOrgEmail']
        pwd1 = request.POST['pwd1']
        pwd2 = request.POST['pwd2']
        if(pwd1 == pwd2):
            org_details_updated = Organization.objects.filter(o_email=tempOrgFpEmail).update(o_password=pwd1)
            if org_details_updated:
                subject = 'MyRemoteDesk - Password was Changed'
                message = f'Hi, Your Password was changed!'
                email_from = settings.EMAIL_HOST_USER
                recipient_list = [tempOrgFpEmail]
                send_mail(subject, message, email_from, recipient_list)
                return render(request, 'OrgFpChangePass.html', {'msg': '10'})
            else:
                return render(request, 'OrgFpChangePass.html', {'msg': '11'})
        else:
            return render(request, 'OrgFpChangePass.html', {'msg': "2"})
    else:
        return render(request, 'OrgFpChangePass.html')

def user_forgot_password(request):
    if request.method == 'POST':
        e_email = request.POST['e_email']
        request.session['tempfpEmpEmail'] = e_email
        emp_details = Employee.objects.filter(e_email=e_email).values()
        if emp_details:
            otp = generateOTP()
            request.session['tempfpEmpOTP'] = otp
            subject = 'MyRemoteDesk - OTP Verification for Forgot Password'
            message = f'Hi {e_email}, Your One Time Password (OTP) for forgot password is {otp}'
            email_from = settings.EMAIL_HOST_USER
            recipient_list = [e_email, ]
            send_mail(subject, message, email_from, recipient_list)
            return HttpResponseRedirect('/user-forgot-password-otp-verify')
        else:
            return render(request, 'Emp_fp.html', {'msg': "0"})
    else:
        return render(request, 'Emp_fp.html')

def user_forgot_password_otp_verify(request):
    if request.method == 'POST':
        fp_emp_otp = request.POST['fp_emp_otp']
        tempEmpFpOTP = request.session['tempfpEmpOTP']
        if(fp_emp_otp == tempEmpFpOTP):
            return HttpResponseRedirect('/user-forgot-password-change-pass')
        else:
            return render(request, 'EmpFpVerifyOTP.html', {'msg': "0"})
    else:
        return render(request, 'EmpFpVerifyOTP.html')

def user_forgot_password_change_password(request):
    if request.method == 'POST':
        tempEmpFpEmail = request.session['tempfpEmpEmail']
        pwd1 = request.POST['pwd1']
        pwd2 = request.POST['pwd2']
        if(pwd1 == pwd2):
            emp_details_updated = Employee.objects.filter(e_email=tempEmpFpEmail).update(e_password=pwd1)
            if emp_details_updated:
                subject = 'MyRemoteDesk - Password was Changed'
                message = f'Hi, Your Password was changed!'
                email_from = settings.EMAIL_HOST_USER
                recipient_list = [tempEmpFpEmail]
                send_mail(subject, message, email_from, recipient_list)
                return render(request, 'EmpFpChangePass.html', {'msg': '10'})
            else:
                return render(request, 'EmpFpChangePass.html', {'msg': '11'})
        else:
            return render(request, 'EmpFpChangePass.html', {'msg': "2"})
    else:
        return render(request, 'EmpFpChangePass.html')

# @privileged_access_required
# @permission_required('report_problems')
# def report_org(request):
#     # Retrieve user details from custom_user
#     cname = request.custom_user.o_name
#     cemail = request.custom_user.o_email
#     if request.method == 'POST':
#         ptype = request.POST['prob_type']
#         cquery = request.POST['rquery']
#         subject = 'MyRemoteDesk - New Enquiry'
#         message = f'Name : {cname}, Email : {cemail}, Problem : {ptype}, Query : {cquery}'
#         email_from = settings.EMAIL_HOST_USER
#         recipient_list = ["narender.rk10@gmail.com",
#                           "2021.narender.keswani@ves.ac.in",
#                           "2021.prathamesh.bhosale@ves.ac.in",
#                           "2021.chinmay.vyapari@ves.ac.in"]
#         send_mail(subject, message, email_from, recipient_list)
#         send_mail(subject, "Your Problem has been recorded. From: MyRemoteDesk", email_from, [cemail])
#         messages.success(request, "Your Problem has been recorded.")
#         return HttpResponseRedirect('/org_report_problems')
#     return render(request, 'OrgReportProblems.html')

@privileged_access_required
@permission_required('report_problems')
def report_org(request):
    # Retrieve user details from custom_user
    cname = request.custom_user.o_name
    cemail = request.custom_user.o_email
    if request.method == 'POST':
        ptype = request.POST['prob_type']
        cquery = request.POST['rquery']
        subject = 'MyRemoteDesk - New Enquiry'
        message = f'Name : {cname}, Email : {cemail}, Problem : {ptype}, Query : {cquery}'
        email_from = settings.EMAIL_HOST_USER
        recipient_list = ["rahulsaini42854@gmail.com",
                          ]
        send_mail(subject, message, email_from, recipient_list)
        send_mail(subject, "Your Problem has been recorded. From: MyRemoteDesk", email_from, [cemail])
        messages.success(request, "Your Problem has been recorded.")
        return HttpResponseRedirect('/org_report_problems')
    return render(request, 'OrgReportProblems.html')

# @privileged_access_required
# @permission_required('report_problems')
# def report_emp(request):
#     # Retrieve user details from custom_user
#     cname = request.custom_user.e_name
#     cemail = request.custom_user.e_email
#     if request.method == 'POST':
#         ptype = request.POST['prob_type']
#         cquery = request.POST['rquery']
#         subject = 'MyRemoteDesk - New Enquiry'
#         message = f'Name : {cname}, Email : {cemail}, Problem : {ptype}, Query : {cquery}'
#         email_from = settings.EMAIL_HOST_USER
#         recipient_list = ["narender.rk10@gmail.com",
#                           "2021.narender.keswani@ves.ac.in",
#                           "2021.prathamesh.bhosale@ves.ac.in",
#                           "2021.chinmay.vyapari@ves.ac.in"]
#         send_mail(subject, message, email_from, recipient_list)
#         send_mail(subject, "Your Problem has been recorded. From: MyRemoteDesk", email_from, [cemail])
#         messages.success(request, "Your Problem has been recorded.")
#         return render(request, 'EmpReportProblems.html')
#     return render(request, 'EmpReportProblems.html')

@privileged_access_required
@permission_required('report_problems')
def report_emp(request):
    # Retrieve user details from custom_user
    cname = request.custom_user.e_name
    cemail = request.custom_user.e_email
    if request.method == 'POST':
        ptype = request.POST['prob_type']
        cquery = request.POST['rquery']
        subject = 'MyRemoteDesk - New Enquiry'
        message = f'Name : {cname}, Email : {cemail}, Problem : {ptype}, Query : {cquery}'
        email_from = settings.EMAIL_HOST_USER
        recipient_list = ["rahulsaini42854@gmail.com",]
        send_mail(subject, message, email_from, recipient_list)
        send_mail(subject, "Your Problem has been recorded. From: MyRemoteDesk", email_from, [cemail])
        messages.success(request, "Your Problem has been recorded.")
        return render(request, 'EmpReportProblems.html')
    return render(request, 'EmpReportProblems.html')

@privileged_access_required
@permission_required('add_employee')
def add_emp(request):
    current_org_id = None
    if request.custom_user.is_org():
        current_org_id = request.custom_user.id
    elif request.custom_user.is_emp():
        current_org_id = request.custom_user.o_id_id

    if not current_org_id:
        messages.error(request, "Failed to determine organization context. Please re-authenticate.")
        return redirect('/LoginOrg') # Redirect to an appropriate login or error page

    if request.method == 'POST':
        e_name = request.POST['e_name']
        e_email = request.POST['e_email']
        e_password = generate_password()
        e_gender = request.POST['e_gender']
        e_contact = request.POST['e_contact']
        e_address = request.POST['e_address']
        role_id = request.POST.get('role_id')

        try:
            empObj = Employee.objects.create(
                e_name=e_name,
                e_email=e_email,
                e_password=e_password,
                e_gender=e_gender,
                e_contact=e_contact,
                e_address=e_address,
                o_id_id=current_org_id,
                role_id=role_id if role_id else None
            )

            subject = 'MyRemoteDesk - Login Info'
            org_name = Organization.objects.get(id=current_org_id).o_name
            message = f'Name : {e_name}, \n Email : {e_email}, \n Password : {e_password} \n Organization : {org_name}'
            email_from = settings.EMAIL_HOST_USER
            send_mail(subject, message, email_from, [e_email])

            messages.success(request, "Employee was added successfully!")
            return HttpResponseRedirect('/create-emp')
        except Exception as e:
            messages.error(request, f"Some error occurred: {str(e)}")
            return HttpResponseRedirect('/create-emp')

    roles = Role.objects.all()
    return render(request, 'AddEmp.html', {'roles': roles})

@privileged_access_required
@permission_required('create_role')
def create_role(request):
    # Organization ID is derived from request.custom_user.id or request.custom_user.o_id_id
    # Roles and Permissions are global in your model, not per organization, so no current_org_id filter needed here for Role creation.
    # However, to avoid 'KeyError: o_id' if this view were to try to use it, let's include the block.
    current_org_id = None
    if request.custom_user.is_org():
        current_org_id = request.custom_user.id
    elif request.custom_user.is_emp():
        current_org_id = request.custom_user.o_id_id
    
    if not current_org_id:
        messages.error(request, "Failed to determine organization context. Please re-authenticate.")
        return redirect('/LoginOrg')

    if request.method == 'POST':
        name = request.POST.get('name')
        description = request.POST.get('description')
        permission_ids = request.POST.getlist('permissions')

        if Role.objects.filter(name=name).exists():
            messages.error(request, f"Role with name '{name}' already exists.")
            return HttpResponseRedirect('/read-role')

        role = Role.objects.create(name=name, description=description)
        if permission_ids:
            role.permissions.set(permission_ids)

        messages.success(request, "Role created successfully!")
        return HttpResponseRedirect('/read-role')
    return HttpResponseRedirect('/read-role') # Redirect on GET, or display form if desired

@privileged_access_required
@permission_required('view_role')
def read_roles(request):
    # See note in create_role about current_org_id. Not directly used for filtering roles here.
    current_org_id = None
    if request.custom_user.is_org():
        current_org_id = request.custom_user.id
    elif request.custom_user.is_emp():
        current_org_id = request.custom_user.o_id_id
    
    if not current_org_id:
        messages.error(request, "Failed to determine organization context. Please re-authenticate.")
        return redirect('/LoginOrg')

    roles = Role.objects.prefetch_related('permissions').all()
    permissions = Permission.objects.all()
    context = {
        'roles': roles,
        'permissions': permissions
    }
    return render(request, 'ManageRoles.html', context)

@privileged_access_required
@permission_required('update_role')
def update_role(request, pk):
    # See note in create_role about current_org_id. Not directly used for filtering roles here.
    current_org_id = None
    if request.custom_user.is_org():
        current_org_id = request.custom_user.id
    elif request.custom_user.is_emp():
        current_org_id = request.custom_user.o_id_id
    
    if not current_org_id:
        messages.error(request, "Failed to determine organization context. Please re-authenticate.")
        return redirect('/LoginOrg')

    role = get_object_or_404(Role, pk=pk)
    if request.method == 'POST':
        name = request.POST.get('name')
        description = request.POST.get('description')
        permission_ids = request.POST.getlist('permissions')

        if Role.objects.filter(name=name).exclude(pk=pk).exists():
            messages.error(request, f"Another role with name '{name}' already exists.")
            return HttpResponseRedirect(f'/update-role/{pk}/')

        role.name = name
        role.description = description
        role.permissions.set(permission_ids)
        role.save()
        messages.success(request, "Role updated successfully!")
        return HttpResponseRedirect('/read-role')
    else:
        permissions = Permission.objects.all()
        context = {
            'role': role,
            'permissions': permissions,
            'assigned_permissions': list(role.permissions.values_list('id', flat=True))
        }
        return render(request, 'UpdateRole.html', context)

@privileged_access_required
@permission_required('delete_role')
def delete_role(request, pk):
    # See note in create_role about current_org_id. Not directly used for filtering roles here.
    current_org_id = None
    if request.custom_user.is_org():
        current_org_id = request.custom_user.id
    elif request.custom_user.is_emp():
        current_org_id = request.custom_user.o_id_id
    
    if not current_org_id:
        messages.error(request, "Failed to determine organization context. Please re-authenticate.")
        return redirect('/LoginOrg')

    try:
        role = Role.objects.get(id=pk)
        role_name = role.name
        role.delete()
        messages.success(request, f"Role '{role_name}' deleted successfully.")
    except Role.DoesNotExist:
        messages.error(request, "Role not found.")
    except Exception as e:
        messages.error(request, f"Error deleting role: {e}")
    return HttpResponseRedirect('/read-role')

# CSRF protection should be handled in templates for POST requests, not disabled with @csrf_exempt
@privileged_access_required
@permission_required('create_permission')
def create_permission(request):
    # See note in create_role about current_org_id. Not directly used for filtering permissions here.
    current_org_id = None
    if request.custom_user.is_org():
        current_org_id = request.custom_user.id
    elif request.custom_user.is_emp():
        current_org_id = request.custom_user.o_id_id
    
    if not current_org_id:
        messages.error(request, "Failed to determine organization context. Please re-authenticate.")
        return redirect('/LoginOrg')

    if request.method == 'POST':
        codename = request.POST.get('codename')
        name = request.POST.get('name')
        description = request.POST.get('description')

        if not codename or not name:
            messages.error(request, "Codename and name are required.")
            return redirect('read-permissions')

        if Permission.objects.filter(codename=codename).exists():
            messages.warning(request, f"Permission with codename '{codename}' already exists.")
            return redirect('read-permissions')

        Permission.objects.create(codename=codename, name=name, description=description)
        messages.success(request, "Permission created successfully!")
        return redirect('read-permissions')

    return redirect('read-permissions') # For GET requests, redirect to read page

@privileged_access_required
@permission_required('view_permission')
def read_permissions(request):
    # See note in create_role about current_org_id. Not directly used for filtering permissions here.
    current_org_id = None
    if request.custom_user.is_org():
        current_org_id = request.custom_user.id
    elif request.custom_user.is_emp():
        current_org_id = request.custom_user.o_id_id
    
    if not current_org_id:
        messages.error(request, "Failed to determine organization context. Please re-authenticate.")
        return redirect('/LoginOrg')

    permissions = Permission.objects.all().order_by('name')
    return render(request, 'ManagePermissions.html', {'permissions': permissions})

@privileged_access_required
@permission_required('update_permission')
def update_permission(request, pk):
    # See note in create_role about current_org_id. Not directly used for filtering permissions here.
    current_org_id = None
    if request.custom_user.is_org():
        current_org_id = request.custom_user.id
    elif request.custom_user.is_emp():
        current_org_id = request.custom_user.o_id_id
    
    if not current_org_id:
        messages.error(request, "Failed to determine organization context. Please re-authenticate.")
        return redirect('/LoginOrg')

    permission = get_object_or_404(Permission, pk=pk)
    if request.method == 'POST':
        codename = request.POST.get('codename')
        name = request.POST.get('name')
        description = request.POST.get('description')

        if Permission.objects.filter(codename=codename).exclude(pk=pk).exists():
            messages.error(request, f"Another permission with codename '{codename}' already exists.")
            return HttpResponseRedirect(f'/update-permission/{pk}/')

        permission.codename = codename
        permission.name = name
        permission.description = description
        permission.save()
        messages.success(request, "Permission updated successfully!")
        return HttpResponseRedirect('/read-permission')
    else:
        return render(request, 'UpdatePermission.html', {'permission': permission})

@privileged_access_required
@permission_required('delete_permission')
def delete_permission(request, pk):
    # See note in create_role about current_org_id. Not directly used for filtering permissions here.
    current_org_id = None
    if request.custom_user.is_org():
        current_org_id = request.custom_user.id
    elif request.custom_user.is_emp():
        current_org_id = request.custom_user.o_id_id
    
    if not current_org_id:
        messages.error(request, "Failed to determine organization context. Please re-authenticate.")
        return redirect('/LoginOrg')

    try:
        permission = Permission.objects.get(id=pk)
        permission_name = permission.name
        permission.delete()
        messages.success(request, f"Permission '{permission_name}' deleted successfully.")
    except Permission.DoesNotExist:
        messages.error(request, "Permission not found.")
    except Exception as e:
        messages.error(request, f"Error deleting permission: {e}")
    return HttpResponseRedirect('/read-permission')

@privileged_access_required
@permission_required('view_employee')
def read_emp(request):
    current_org_id = None
    if request.custom_user.is_org():
        current_org_id = request.custom_user.id
    elif request.custom_user.is_emp():
        current_org_id = request.custom_user.o_id_id
    
    if not current_org_id:
        messages.error(request, "Failed to determine organization context. Please re-authenticate.")
        return redirect('/LoginOrg')

    if request.method == 'GET':
        emp_details = Employee.objects.filter(o_id_id=current_org_id).all()
        return render(request, 'ViewEmp.html', {"msg": emp_details})

@privileged_access_required
@permission_required('create_board')
def create_board(request):
    current_org_id = None
    if request.custom_user.is_org():
        current_org_id = request.custom_user.id
    elif request.custom_user.is_emp():
        current_org_id = request.custom_user.o_id_id
    
    if not current_org_id:
        messages.error(request, "Failed to determine organization context. Please re-authenticate.")
        return redirect('/LoginOrg')

    if request.method == 'POST':
        b_name = request.POST['b_name']
        boardCheck = Board.objects.filter(b_name=b_name, o_id_id=current_org_id)
        if boardCheck:
            messages.error(request, "Board already exists!")
            return HttpResponseRedirect('/create-board')
        else:
            boardObj = Board.objects.create(b_name=b_name, o_id_id=current_org_id)
            if boardObj:
                messages.success(request, "Board created successfully!")
                return HttpResponseRedirect('/create-board')
            else:
                messages.error(request, "Some error was occurred!")
                return HttpResponseRedirect('/create-board')
    return render(request, 'AddBoard.html')

@privileged_access_required
@permission_required('view_board')
def read_boards(request):
    current_org_id = None
    if request.custom_user.is_org():
        current_org_id = request.custom_user.id
    elif request.custom_user.is_emp():
        current_org_id = request.custom_user.o_id_id
    
    if not current_org_id:
        messages.error(request, "Failed to determine organization context. Please re-authenticate.")
        return redirect('/LoginOrg')

    if request.method == 'GET':
        board_details = Board.objects.filter(o_id_id=current_org_id).values()
        return render(request, 'ViewBoards.html', {"msg": board_details})

@privileged_access_required
@permission_required('create_project')
def create_proj(request):
    current_org_id = None
    if request.custom_user.is_org():
        current_org_id = request.custom_user.id
    elif request.custom_user.is_emp():
        current_org_id = request.custom_user.o_id_id
    
    if not current_org_id:
        messages.error(request, "Failed to determine organization context. Please re-authenticate.")
        return redirect('/LoginOrg')

    if request.method == 'POST':
        p_name = request.POST['p_name']
        p_desc = request.POST['p_desc']
        projCheck = Project.objects.filter(p_name=p_name, o_id_id=current_org_id)
        if projCheck:
            messages.error(request, "Project already exists!")
            return HttpResponseRedirect('/create-proj')
        else:
            projObj = Project.objects.create(
                p_name=p_name, p_desc=p_desc, o_id_id=current_org_id)
            if projObj:
                messages.success(request, "Project added successfully!")
                return HttpResponseRedirect('/create-proj')
            else:
                messages.error(request, "Some Error was occurred!")
                return HttpResponseRedirect('/create-proj')
    return render(request, 'OrgCreateProject.html')

@privileged_access_required
@permission_required('view_project')
def read_proj(request):
    current_org_id = None
    if request.custom_user.is_org():
        current_org_id = request.custom_user.id
    elif request.custom_user.is_emp():
        current_org_id = request.custom_user.o_id_id
    
    if not current_org_id:
        messages.error(request, "Failed to determine organization context. Please re-authenticate.")
        return redirect('/LoginOrg')

    if request.method == 'GET':
        project_details = Project.objects.filter(o_id_id=current_org_id).values()
        return render(request, 'ViewProjects.html', {"msg": project_details})

@privileged_access_required
@permission_required('view_project_tasks')
def projectwise_task(request,pid):
    current_org_id = None
    if request.custom_user.is_org():
        current_org_id = request.custom_user.id
    elif request.custom_user.is_emp():
        current_org_id = request.custom_user.o_id_id
    
    if not current_org_id:
        messages.error(request, "Failed to determine organization context. Please re-authenticate.")
        return redirect('/LoginOrg')

    if request.method == 'GET':
        project_details = Project.objects.filter(o_id_id=current_org_id, id=pid).all()
        tasks = Task.objects.filter(o_id_id=current_org_id, p_id_id=pid).all()
        count_no_of_total_tasks = Task.objects.filter(o_id_id=current_org_id, p_id_id=pid).count()
        count_no_of_completed_tasks = Task.objects.filter(o_id_id=current_org_id, p_id_id=pid, t_status="completed").count()
        count_no_of_pending_tasks = count_no_of_total_tasks - count_no_of_completed_tasks
        if tasks:
            tasklist = []
            for task in tasks:
                Dict = {}
                Dict["Task"] = task.t_name
                Dict["Start"] = task.t_assign_date
                Dict["Finish"] = task.t_deadline_date
                Dict["Resource"] = task.t_priority
                tasklist.append(Dict)
            df = pd.DataFrame(tasklist)
            fig = px.timeline(df, x_start="Start", x_end="Finish", y="Task", color="Resource")
            fig.update_yaxes(autorange="reversed")
            plot_div = plot(fig, output_type='div')
            context = {"project_details": project_details, 'plot_div': plot_div, 'task_total': count_no_of_total_tasks, 'task_completed': count_no_of_completed_tasks, 'task_pending': count_no_of_pending_tasks }
            return render(request, 'ViewProjectwiseTasks.html', context)
        else:
            messages.info(request, "No tasks found for this project.")
            return render(request, 'ViewProjectwiseTasks.html')

@user_login_required # Employee's own tasks, so use user_login_required
def user_projectwise_task(request,pid):
    current_org_id = request.custom_user.o_id_id
    current_emp_id = request.custom_user.id

    project_details = Project.objects.filter(o_id_id=current_org_id, id=pid).all()
    tasks = Task.objects.filter(o_id_id=current_org_id, p_id_id=pid, e_id_id=current_emp_id).all()
    count_no_of_total_tasks = Task.objects.filter(o_id_id=current_org_id, e_id_id=current_emp_id,  p_id_id=pid).count()
    count_no_of_completed_tasks = Task.objects.filter(o_id_id=current_org_id, e_id_id=current_emp_id, p_id_id=pid, t_status="completed").count()
    count_no_of_pending_tasks = count_no_of_total_tasks - count_no_of_completed_tasks
    if tasks:
        tasklist = []
        for task in tasks:
            Dict = {}
            Dict["Task"] = task.t_name
            Dict["Start"] = task.t_assign_date
            Dict["Finish"] = task.t_deadline_date
            Dict["Resource"] = task.t_priority
            tasklist.append(Dict)
        df = pd.DataFrame(tasklist)
        fig = px.timeline(df, x_start="Start", x_end="Finish", y="Task", color="Resource")
        fig.update_yaxes(autorange="reversed")
        plot_div = plot(fig, output_type='div')
        context = {"project_details": project_details, 'plot_div': plot_div, 'task_total': count_no_of_total_tasks,
                   'task_completed': count_no_of_completed_tasks, 'task_pending': count_no_of_pending_tasks}
        return render(request, 'EmpViewProjectwiseTasks.html', context)
    else:
        messages.info(request, "No tasks found for this project for you.")
        return render(request, 'EmpViewProjectwiseTasks.html')

@privileged_access_required
@permission_required('view_board_tasks')
def boardwise_task(request,bid):
    current_org_id = None
    if request.custom_user.is_org():
        current_org_id = request.custom_user.id
    elif request.custom_user.is_emp():
        current_org_id = request.custom_user.o_id_id
    
    if not current_org_id:
        messages.error(request, "Failed to determine organization context. Please re-authenticate.")
        return redirect('/LoginOrg')

    if request.method == 'GET':
        board_details = Board.objects.filter(o_id_id=current_org_id,id=bid).all()
        context = {"board_details": board_details}
        return render(request, 'ViewBoardwiseTasks.html', context)

@privileged_access_required
@permission_required('view_meeting')
def read_meet(request):
    current_org_id = None
    if request.custom_user.is_org():
        current_org_id = request.custom_user.id
    elif request.custom_user.is_emp():
        current_org_id = request.custom_user.o_id_id
    
    if not current_org_id:
        messages.error(request, "Failed to determine organization context. Please re-authenticate.")
        return redirect('/LoginOrg')

    if request.method == 'GET':
        meeting_details = Meeting.objects.filter(o_id_id=current_org_id).values()
        return render(request, 'ViewMeeting.html', {"msg": meeting_details})

@user_login_required # Employee's own meetings, no specific permission needed
def user_read_meets(request):
    current_org_id = request.custom_user.o_id_id
    current_emp_id = request.custom_user.id

    if request.method == 'GET':
        pel_details = Project_Employee_Linker.objects.filter(o_id_id=current_org_id, e_id_id=current_emp_id).order_by('-id').values_list('p_id_id', flat=True)
        meeting_details = Meeting.objects.filter(p_id_id__in=pel_details).values()
        return render(request, 'EmpViewMeeting.html', {"msg": meeting_details})

@privileged_access_required
@permission_required('assign_project')
def assign_proj_emp(request):
    current_org_id = None
    if request.custom_user.is_org():
        current_org_id = request.custom_user.id
    elif request.custom_user.is_emp():
        current_org_id = request.custom_user.o_id_id
    
    if not current_org_id:
        messages.error(request, "Failed to determine organization context. Please re-authenticate.")
        return redirect('/LoginOrg')

    projAssign_details = Project_Employee_Linker.objects.filter(o_id_id=current_org_id).prefetch_related('p_id','e_id') # Changed to prefetch_related on models, not id's
    project_details = Project.objects.filter(o_id_id=current_org_id).values()
    emp_details = Employee.objects.filter(o_id_id=current_org_id).values()
    if request.method == 'POST':
        p_id = request.POST['p_id']
        e_id = request.POST['e_id']
        projAssignCheck = Project_Employee_Linker.objects.filter(p_id_id=p_id, e_id_id=e_id, o_id_id=current_org_id)
        if projAssignCheck:
            messages.error(request, "Employee already assigned to this project!")
            return HttpResponseRedirect('/assign-proj')
        else:
            projAssignCheckObj = Project_Employee_Linker.objects.create(e_id_id = e_id, o_id_id = current_org_id, p_id_id = p_id)
            if projAssignCheckObj:
                user_details = Employee.objects.filter(id=e_id,o_id_id=current_org_id).values()
                s_email = user_details[0]["e_email"]
                s_name = user_details[0]["e_name"]
                project_details_for_email = Project.objects.filter(o_id_id=current_org_id,id=p_id).values()
                s_p_name = project_details_for_email[0]["p_name"]
                if user_details and project_details_for_email:
                    subject = 'MyRemoteDesk - Project was Assigned to you'
                    message = f'Hi, {s_name} You are asssigned to project {s_p_name} Check on MyRemoteDesk !'
                    email_from = settings.EMAIL_HOST_USER
                    recipient_list = [s_email]
                    send_mail(subject, message, email_from, recipient_list)
                messages.success(request, "Employee was Successfully Assigned with Project!")
                return HttpResponseRedirect('/assign-proj')
            else:
                messages.error(request, "Error was occurred!")
                return HttpResponseRedirect('/assign-proj')
    return render(request, 'AssignProjEmp.html', {'msg1':project_details,'msg2':emp_details,'msg3':projAssign_details})

@privileged_access_required
@permission_required('create_meeting')
def create_meet(request):
    current_org_id = None
    if request.custom_user.is_org():
        current_org_id = request.custom_user.id
    elif request.custom_user.is_emp():
        current_org_id = request.custom_user.o_id_id
    
    if not current_org_id:
        messages.error(request, "Failed to determine organization context. Please re-authenticate.")
        return redirect('/LoginOrg')

    project_details = Project.objects.filter(o_id_id=current_org_id).values()
    if request.method == 'POST':
        p_id = request.POST['p_id']
        m_name = request.POST['m_name']
        m_desc = request.POST['m_desc']
        start_date = request.POST['start_date']
        stop_date = request.POST['stop_date']
        start_time = request.POST['start_time']
        stop_time = request.POST['stop_time']
        m_uuid = uuid.uuid1()
        meetingObj = Meeting.objects.create(m_name = m_name, m_desc = m_desc, m_uuid = m_uuid, m_start_date = start_date, m_start_time = start_time, m_stop_date = stop_date, m_stop_time = stop_time, p_id_id = p_id, o_id_id = current_org_id)
        if meetingObj:
            pel_details = Project_Employee_Linker.objects.filter(o_id_id=current_org_id,p_id_id=p_id).values_list('e_id_id', flat=True)
            user_details = Employee.objects.filter(id__in=pel_details).values()
            if user_details:
                for ud in user_details:
                    subject = 'MyRemoteDesk - New Meeting'
                    s_name = ud['e_name']
                    s_email = ud['e_email']
                    message = f'Hi, {s_name} New Meeting created for you! Details are Meeting Name :{m_name}, Meeting Description: {m_desc}, Date Time: {start_date} {start_time} Check on MyRemoteDesk !'
                    email_from = settings.EMAIL_HOST_USER
                    recipient_list = [s_email]
                    send_mail(subject, message, email_from, recipient_list)
            messages.success(request,"Meeting is created successfully!")
            return HttpResponseRedirect('/create-meet')
        else:
            messages.error(request, "Some error was occurred!")
            return HttpResponseRedirect('/create-meet')
    return render(request, 'AddMeeting.html', {'msg1':project_details})

@privileged_access_required
@permission_required('view_employee')
def view_emp(request,eid):
    current_org_id = None
    if request.custom_user.is_org():
        current_org_id = request.custom_user.id
    elif request.custom_user.is_emp():
        current_org_id = request.custom_user.o_id_id
    
    if not current_org_id:
        messages.error(request, "Failed to determine organization context. Please re-authenticate.")
        return redirect('/LoginOrg')

    if request.method == 'GET':
        emp_details = Employee.objects.filter(o_id_id=current_org_id, id=eid).first()
        count_no_of_total_tasks = Task.objects.filter(o_id_id=current_org_id, e_id_id=eid).count()
        count_no_of_completed_tasks = Task.objects.filter(o_id_id=current_org_id, e_id_id=eid, t_status="completed").count()
        count_no_of_pending_tasks = count_no_of_total_tasks - count_no_of_completed_tasks
        pel_details = Project_Employee_Linker.objects.filter(o_id_id=current_org_id, e_id_id=eid).values_list('p_id_id', flat=True)
        project_details = Project.objects.filter(id__in=pel_details).values()
        return render(request, 'EmpDetails.html', {"msg": emp_details, "msg1": count_no_of_total_tasks, "msg2": count_no_of_completed_tasks, "msg3": count_no_of_pending_tasks, "msg4": project_details})

@privileged_access_required
@permission_required('update_employee')
def update_emp(request, eid):
    current_org_id = None
    if request.custom_user.is_org():
        current_org_id = request.custom_user.id
    elif request.custom_user.is_emp():
        current_org_id = request.custom_user.o_id_id
    
    if not current_org_id:
        messages.error(request, "Failed to determine organization context. Please re-authenticate.")
        return redirect('/LoginOrg')

    try:
        emp_detail = get_object_or_404(Employee, id=eid, o_id_id=current_org_id)

        if request.method == "POST":
            emp_detail.e_name = request.POST['e_name']
            emp_detail.e_gender = request.POST['e_gender']
            emp_detail.e_contact = request.POST['e_contact']
            emp_detail.e_address = request.POST['e_address']

            role_id = request.POST.get('role_id')
            if role_id and role_id.isdigit():
                emp_detail.role_id = int(role_id)
            else:
                emp_detail.role = None

            emp_detail.save()
            messages.success(request, "Employee Data was updated successfully!")
            return HttpResponseRedirect('/read-emp')
        else:
            all_roles = Role.objects.all()
            context = {
                'emp_detail': emp_detail,
                'roles': all_roles
            }
            return render(request, 'UpdateEmp.html', context)
    except Employee.DoesNotExist:
        messages.error(request, "Employee not found.")
        return HttpResponseRedirect('/read-emp')
    except Exception as e:
        messages.error(request, f"Some Error was occurred: {e}")
        return HttpResponseRedirect('/read-emp')

@privileged_access_required
@permission_required('delete_employee')
def del_emp(request, eid):
    current_org_id = None
    if request.custom_user.is_org():
        current_org_id = request.custom_user.id
    elif request.custom_user.is_emp():
        current_org_id = request.custom_user.o_id_id
    
    if not current_org_id:
        messages.error(request, "Failed to determine organization context. Please re-authenticate.")
        return redirect('/LoginOrg')

    try:
        emp_detail = Employee.objects.filter(id=eid,o_id_id=current_org_id).delete()
        if emp_detail[0] > 0:
            messages.success(request, "Employee was deleted successfully!")
            return HttpResponseRedirect('/read-emp')
        else:
            messages.error(request, "Some Error was occurred!")
            return HttpResponseRedirect('/read-emp')
    except Exception as e:
        messages.error(request, f"Some Error was occurred: {e}")
        return HttpResponseRedirect('/read-emp')

@privileged_access_required
@permission_required('delete_board')
def del_board(request, bid):
    current_org_id = None
    if request.custom_user.is_org():
        current_org_id = request.custom_user.id
    elif request.custom_user.is_emp():
        current_org_id = request.custom_user.o_id_id
    
    if not current_org_id:
        messages.error(request, "Failed to determine organization context. Please re-authenticate.")
        return redirect('/LoginOrg')

    try:
        board_detail = Board.objects.filter(id=bid,o_id_id=current_org_id).delete()
        if board_detail[0] > 0:
            messages.success(request, "Board was deleted successfully!")
            return HttpResponseRedirect('/read-boards')
        else:
            messages.error(request, "Some Error was occurred!")
            return HttpResponseRedirect('/read-boards')
    except Exception as e:
        messages.error(request, f"Some Error was occurred: {e}")
        return HttpResponseRedirect('/read-boards')

@privileged_access_required
@permission_required('delete_project')
def del_proj(request, pid):
    current_org_id = None
    if request.custom_user.is_org():
        current_org_id = request.custom_user.id
    elif request.custom_user.is_emp():
        current_org_id = request.custom_user.o_id_id
    
    if not current_org_id:
        messages.error(request, "Failed to determine organization context. Please re-authenticate.")
        return redirect('/LoginOrg')

    try:
        project_detail = Project.objects.filter(id=pid,o_id_id=current_org_id).delete()
        if project_detail[0] > 0:
            messages.success(request, "Project was deleted successfully!")
            return HttpResponseRedirect('/read-proj')
        else:
            messages.error(request, "Some Error was occurred!")
            return HttpResponseRedirect('/read-proj')
    except Exception as e:
        messages.error(request, f"Some Error was occurred: {e}")
        return HttpResponseRedirect('/read-proj')

# @privileged_access_required
# @permission_required('view_app_web_logs')
# def view_app_web(request):
#     current_org_id = None
#     if request.custom_user.is_org():
#         current_org_id = request.custom_user.id
#     elif request.custom_user.is_emp():
#         current_org_id = request.custom_user.o_id_id
    
#     if not current_org_id:
#         messages.error(request, "Failed to determine organization context. Please re-authenticate.")
#         return redirect('/LoginOrg')

#     if request.method == 'POST':
#         e_id = request.POST['e_id']
#         m_date = request.POST['date_log']
#         m_date_f1 = datetime.datetime.strptime(m_date, '%Y-%m-%d')
#         m_date_f2 = datetime.datetime.strftime(m_date_f1, '%Y-%m-%d')
#         moni_details = Monitoring.objects.filter(o_id_id=current_org_id, e_id_id=e_id, m_log_ts__startswith=m_date_f2).exclude(m_title="").values()
#         return render(request, 'ViewMoniLogs.html', {"msg": moni_details})
#     else: # GET request
#         emp_details = Employee.objects.filter(o_id_id=current_org_id).values()
#         return render(request, 'SelectMoniEmp.html', {"msg": emp_details})


@privileged_access_required
@permission_required('view_app_web_logs')
def view_app_web(request):
    current_org_id = None
    if request.custom_user.is_org():
        current_org_id = request.custom_user.id
    elif request.custom_user.is_emp():
        current_org_id = request.custom_user.o_id_id
    
    if not current_org_id:
        messages.error(request, "Failed to determine organization context. Please re-authenticate.")
        return redirect('/LoginOrg')

    if request.method == 'POST':
        e_id = request.POST['e_id']
        m_date = request.POST['date_log']
        
        m_date_f1 = datetime.datetime.strptime(m_date, '%Y-%m-%d')
        # FIX: Ensure YYYY-MM-DD format without platform-specific modifiers
        m_date_f2 = m_date_f1.strftime('%Y-%m-%d') # Changed from '%Y-%#m-%#d'

        # Debug prints
        print(f"DEBUG (view_app_web): Filtering for e_id={e_id}, o_id={current_org_id}, date='{m_date_f2}'")
        
        moni_details = Monitoring.objects.filter(
            o_id_id=current_org_id,
            e_id_id=e_id,
            m_log_ts__startswith=m_date_f2
        ).exclude(m_title="").values()

        print(f"DEBUG (view_app_web): Found {len(moni_details)} records.")
        if moni_details:
            print(f"DEBUG (view_app_web): First record m_title: {moni_details[0]['m_title']}, m_log_ts: {moni_details[0]['m_log_ts']}")

        return render(request, 'ViewMoniLogs.html', {"msg": moni_details})
    else: # GET request
        emp_details = Employee.objects.filter(o_id_id=current_org_id).values()
        return render(request, 'SelectMoniEmp.html', {"msg": emp_details})



# @user_login_required # Employee's own logs, specific permission not required
# def user_view_app_web(request):
#     current_org_id = request.custom_user.o_id_id
#     current_emp_id = request.custom_user.id

#     if request.method == 'POST':
#         m_date = request.POST['date_log']
#         m_date_f1 = datetime.datetime.strptime(m_date, '%Y-%m-%d')
#         m_date_f2 = datetime.datetime.strftime(m_date_f1, '%Y-%m-%d')
#         moni_details = Monitoring.objects.filter(o_id_id=current_org_id, e_id_id=current_emp_id, m_log_ts__startswith=m_date_f2).exclude(m_title="").values()
#         return render(request, 'EmpViewMoniLogs.html', {"msg": moni_details})
#     else:
#         return render(request, 'EmpSelectMoniEmp.html')

@user_login_required
def user_view_app_web(request):
    current_org_id = request.custom_user.o_id_id
    current_emp_id = request.custom_user.id

    if request.method == 'POST':
        m_date = request.POST['date_log']
        
        m_date_f1 = datetime.datetime.strptime(m_date, '%Y-%m-%d')
        # FIX: Ensure YYYY-MM-DD format without platform-specific modifiers
        m_date_f2 = m_date_f1.strftime('%Y-%m-%d') # Changed from '%Y-%#m-%#d'

        # Debug prints
        print(f"DEBUG (user_view_app_web): Filtering for e_id={current_emp_id}, o_id={current_org_id}, date='{m_date_f2}'")

        moni_details = Monitoring.objects.filter(
            o_id_id=current_org_id,
            e_id_id=current_emp_id,
            m_log_ts__startswith=m_date_f2
        ).exclude(m_title="").values()

        print(f"DEBUG (user_view_app_web): Found {len(moni_details)} records.")
        if moni_details:
            print(f"DEBUG (user_view_app_web): First record m_title: {moni_details[0]['m_title']}, m_log_ts: {moni_details[0]['m_log_ts']}")

        return render(request, 'EmpViewMoniLogs.html', {"msg": moni_details})
    else:
        return render(request, 'EmpSelectMoniEmp.html')


# @privileged_access_required
# @permission_required('view_detailed_app_web_logs')
# def depth_view_app_web(request):
#     current_org_id = None
#     if request.custom_user.is_org():
#         current_org_id = request.custom_user.id
#     elif request.custom_user.is_emp():
#         current_org_id = request.custom_user.o_id_id
    
#     if not current_org_id:
#         messages.error(request, "Failed to determine organization context. Please re-authenticate.")
#         return redirect('/LoginOrg')

#     if request.method == 'POST':
#         e_id = request.POST['e_id']
#         md_date = request.POST['date_log']
#         md_date_f1 = datetime.datetime.strptime(md_date, '%Y-%m-%d')
#         md_date_f2 = datetime.datetime.strftime(md_date_f1, '%Y-%#m-%#d')
#         depth_moni_details = MonitoringDetails.objects.filter(o_id_id=current_org_id, e_id_id=e_id,  md_date__startswith=md_date_f2).exclude(md_title="").values()
#         return render(request, 'ViewDepthMoniLogs.html', {"msg": depth_moni_details})
#     else: # GET request
#         emp_details = Employee.objects.filter(o_id_id=current_org_id).values()
#         return render(request, 'SelectDepthMoniEmp.html', {"msg": emp_details})

@privileged_access_required
@permission_required('view_detailed_app_web_logs')
def depth_view_app_web(request):
    current_org_id = None
    if request.custom_user.is_org():
        current_org_id = request.custom_user.id
    elif request.custom_user.is_emp():
        current_org_id = request.custom_user.o_id_id
    
    if not current_org_id:
        messages.error(request, "Failed to determine organization context. Please re-authenticate.")
        return redirect('/LoginOrg')

    if request.method == 'POST':
        e_id = request.POST['e_id']
        md_date = request.POST['date_log']
        
        md_date_f1 = datetime.datetime.strptime(md_date, '%Y-%m-%d')
        # FIX: Ensure YYYY-MM-DD format without platform-specific modifiers
        md_date_f2 = md_date_f1.strftime('%Y-%m-%d') # Changed from '%Y-%#m-%#d'

        # Debug prints
        print(f"DEBUG (depth_view_app_web): Filtering for e_id={e_id}, o_id={current_org_id}, date='{md_date_f2}'")
        
        depth_moni_details = MonitoringDetails.objects.filter(
            o_id_id=current_org_id,
            e_id_id=e_id,
            md_date__startswith=md_date_f2 # Or just md_date=md_date_f2 if md_date is 'YYYY-MM-DD'
        ).exclude(md_title="").values()

        print(f"DEBUG (depth_view_app_web): Found {len(depth_moni_details)} records.")
        if depth_moni_details:
            print(f"DEBUG (depth_view_app_web): First record md_title: {depth_moni_details[0]['md_title']}, md_date: {depth_moni_details[0]['md_date']}")

        return render(request, 'ViewDepthMoniLogs.html', {"msg": depth_moni_details})
    else: # GET request
        emp_details = Employee.objects.filter(o_id_id=current_org_id).values()
        return render(request, 'SelectDepthMoniEmp.html', {"msg": emp_details})


# @user_login_required # Employee's own logs, specific permission not required
# def user_depth_view_app_web(request):
#     current_org_id = request.custom_user.o_id_id
#     current_emp_id = request.custom_user.id

#     if request.method == 'POST':
#         md_date = request.POST['date_log']
#         md_date_f1 = datetime.datetime.strptime(md_date, '%Y-%m-%d')
#         md_date_f2 = datetime.datetime.strftime(md_date_f1, '%Y-%#m-%#d')
#         depth_moni_details = MonitoringDetails.objects.filter(o_id_id=current_org_id, e_id_id=current_emp_id,  md_date__startswith=md_date_f2).exclude(md_title="").values()
#         return render(request, 'EmpViewDepthMoniLogs.html', {"msg": depth_moni_details})
#     else:
#         return render(request, 'EmpSelectDepthMoniEmp.html')



@user_login_required
def user_depth_view_app_web(request):
    current_org_id = request.custom_user.o_id_id
    current_emp_id = request.custom_user.id

    if request.method == 'POST':
        md_date = request.POST['date_log']
        
        md_date_f1 = datetime.datetime.strptime(md_date, '%Y-%m-%d')
        # FIX: Ensure YYYY-MM-DD format without platform-specific modifiers
        md_date_f2 = md_date_f1.strftime('%Y-%m-%d') # Changed from '%Y-%#m-%#d'

        # Debug prints
        print(f"DEBUG (user_depth_view_app_web): Filtering for e_id={current_emp_id}, o_id={current_org_id}, date='{md_date_f2}'")

        depth_moni_details = MonitoringDetails.objects.filter(
            o_id_id=current_org_id,
            e_id_id=current_emp_id,
            md_date__startswith=md_date_f2
        ).exclude(md_title="").values()

        print(f"DEBUG (user_depth_view_app_web): Found {len(depth_moni_details)} records.")
        if depth_moni_details:
            print(f"DEBUG (user_depth_view_app_web): First record md_title: {depth_moni_details[0]['md_title']}, md_date: {depth_moni_details[0]['md_date']}")

        return render(request, 'EmpViewDepthMoniLogs.html', {"msg": depth_moni_details})
    else:
        return render(request, 'EmpSelectDepthMoniEmp.html')

@user_login_required # Employee's own profile, no specific permission needed
def user_profile(request):
    current_org_id = request.custom_user.o_id_id
    current_emp_id = request.custom_user.id

    if request.method == 'GET':
        emp_details = Employee.objects.filter(o_id_id=current_org_id, id=current_emp_id).first()
        count_no_of_total_tasks = Task.objects.filter(o_id_id=current_org_id, e_id_id=current_emp_id).count()
        count_no_of_completed_tasks = Task.objects.filter(o_id_id=current_org_id, e_id_id=current_emp_id, t_status="completed").count()
        count_no_of_pending_tasks = count_no_of_total_tasks - count_no_of_completed_tasks
        pel_details = Project_Employee_Linker.objects.filter(o_id_id=current_org_id, e_id_id=current_emp_id).values_list('p_id_id', flat=True)
        project_details = Project.objects.filter(id__in=pel_details).values()
        return render(request, 'EmpProfile.html', {"msg": emp_details, "msg1": count_no_of_total_tasks, "msg2": count_no_of_completed_tasks, "msg3": count_no_of_pending_tasks, "msg4": project_details})

# @privileged_access_required
# @permission_required('view_screenshots')
# def ss_monitoring(request):
#     current_org_id = None
#     if request.custom_user.is_org():
#         current_org_id = request.custom_user.id
#     elif request.custom_user.is_emp():
#         current_org_id = request.custom_user.o_id_id
    
#     if not current_org_id:
#         messages.error(request, "Failed to determine organization context. Please re-authenticate.")
#         return redirect('/LoginOrg')

#     if request.method == 'POST':
#         e_id = request.POST['e_id']
#         ss_date = request.POST['date_log']
#         ss_date_f1 = datetime.datetime.strptime(ss_date, '%Y-%m-%d')
#         ss_date_f2 = datetime.datetime.strftime(ss_date_f1, '%Y-%#m-%#d')
#         ss_moni_details = ScreenShotsMonitoring.objects.filter(o_id_id=current_org_id, e_id_id=e_id, ssm_log_ts__startswith=ss_date_f2).values()
#         return render(request, 'ViewSSMoniLogs.html', {"msg": ss_moni_details})
#     else: # GET request
#         emp_details = Employee.objects.filter(o_id_id=current_org_id).values()
#         return render(request, 'SelectSSMoniEmp.html', {"msg": emp_details})



@privileged_access_required
@permission_required('view_screenshots')
def ss_monitoring(request):
    current_org_id = None
    if request.custom_user.is_org():
        current_org_id = request.custom_user.id
    elif request.custom_user.is_emp():
        current_org_id = request.custom_user.o_id_id
    
    if not current_org_id:
        messages.error(request, "Failed to determine organization context. Please re-authenticate.")
        return redirect('/LoginOrg')

    if request.method == 'POST':
        e_id = request.POST['e_id']
        ss_date = request.POST['date_log'] # This will be 'YYYY-MM-DD' from the form

        # Convert the date string to a datetime object.
        # This also ensures it's parsed correctly regardless of browser's exact output format.
        ss_date_dt_obj = datetime.datetime.strptime(ss_date, '%Y-%m-%d')
        
        # Format the datetime object back to a string that is guaranteed to be 'YYYY-MM-DD'
        # This will consistently produce '2025-08-05' (with leading zeros if needed)
        # which matches the start of your '2025-08-05 11:32:21.477' timestamps.
        ss_date_filter_str = ss_date_dt_obj.strftime('%Y-%m-%d') 

        # --- ADD THESE DEBUG PRINTS TEMPORARILY ---
        print(f"DEBUG: ss_monitoring - Filtering for e_id={e_id}, o_id={current_org_id}")
        print(f"DEBUG: Input date from form: {ss_date}")
        print(f"DEBUG: Date string used for filter: {ss_date_filter_str}")
        # --- END DEBUG PRINTS ---

        ss_moni_details = ScreenShotsMonitoring.objects.filter(
            o_id_id=current_org_id,
            e_id_id=e_id,
            ssm_log_ts__startswith=ss_date_filter_str # Use the correctly formatted string
        ).values()

        # --- ADD THESE DEBUG PRINTS TEMPORARILY ---
        print(f"DEBUG: ss_monitoring - Found {len(ss_moni_details)} screenshots for this query.")
        if ss_moni_details:
            # Print first entry's relevant data to confirm retrieval and format
            first_ss_img_len = len(ss_moni_details[0]['ssm_img']) if ss_moni_details[0]['ssm_img'] else 'None'
            print(f"DEBUG: First screenshot data length: {first_ss_img_len}")
            print(f"DEBUG: First screenshot ssm_log_ts: {ss_moni_details[0]['ssm_log_ts']}")
        # --- END DEBUG PRINTS ---

        return render(request, 'ViewSSMoniLogs.html', {"msg": ss_moni_details})
    else: # GET request
        emp_details = Employee.objects.filter(o_id_id=current_org_id).values()
        return render(request, 'SelectSSMoniEmp.html', {"msg": emp_details})


# @user_login_required # Employee's own screenshots, specific permission not required
# def user_ss_monitoring(request):
#     current_org_id = request.custom_user.o_id_id
#     current_emp_id = request.custom_user.id

#     if request.method == 'POST':
#         ss_date = request.POST['date_log']
#         ss_date_f1 = datetime.datetime.strptime(ss_date, '%Y-%m-%d')
#         ss_date_f2 = datetime.datetime.strftime(ss_date_f1, '%Y-%#m-%#d')
#         ss_moni_details = ScreenShotsMonitoring.objects.filter(o_id_id=current_org_id, e_id_id=current_emp_id, ssm_log_ts__startswith=ss_date_f2).values()
#         return render(request, 'EmpViewSSMoniLogs.html', {"msg": ss_moni_details})
#     else:
#         return render(request, 'EmpSelectSSMoniEmp.html')

@user_login_required # Employee's own screenshots, specific permission not required
def user_ss_monitoring(request):
    current_org_id = request.custom_user.o_id_id
    current_emp_id = request.custom_user.id

    if request.method == 'POST':
        ss_date = request.POST['date_log'] # This will be 'YYYY-MM-DD' from the form

        ss_date_dt_obj = datetime.datetime.strptime(ss_date, '%Y-%m-%d')
        ss_date_filter_str = ss_date_dt_obj.strftime('%Y-%m-%d') 

        # --- ADD THESE DEBUG PRINTS TEMPORARILY ---
        print(f"DEBUG: user_ss_monitoring - Filtering for e_id={current_emp_id}, o_id={current_org_id}")
        print(f"DEBUG: Input date from form: {ss_date}")
        print(f"DEBUG: Date string used for filter: {ss_date_filter_str}")
        # --- END DEBUG PRINTS ---

        ss_moni_details = ScreenShotsMonitoring.objects.filter(
            o_id_id=current_org_id,
            e_id_id=current_emp_id,
            ssm_log_ts__startswith=ss_date_filter_str
        ).values()

        # --- ADD THESE DEBUG PRINTS TEMPORARILY ---
        print(f"DEBUG: user_ss_monitoring - Found {len(ss_moni_details)} screenshots for this query.")
        if ss_moni_details:
            first_ss_img_len = len(ss_moni_details[0]['ssm_img']) if ss_moni_details[0]['ssm_img'] else 'None'
            print(f"DEBUG: First screenshot data length: {first_ss_img_len}")
            print(f"DEBUG: First screenshot ssm_log_ts: {ss_moni_details[0]['ssm_log_ts']}")
        # --- END DEBUG PRINTS ---

        return render(request, 'EmpViewSSMoniLogs.html', {"msg": ss_moni_details})
    else:
        return render(request, 'EmpSelectSSMoniEmp.html')

# @privileged_access_required
# @permission_required('view_power_logs')
# def power_monitoring(request):
#     current_org_id = None
#     if request.custom_user.is_org():
#         current_org_id = request.custom_user.id
#     elif request.custom_user.is_emp():
#         current_org_id = request.custom_user.o_id_id
    
#     if not current_org_id:
#         messages.error(request, "Failed to determine organization context. Please re-authenticate.")
#         return redirect('/LoginOrg')

#     if request.method == 'POST':
#         e_id = request.POST['e_id']
#         pm_date = request.POST['date_log']
#         pm_date_f1 = datetime.datetime.strptime(pm_date, '%Y-%m-%d')
#         pm_date_f2 = datetime.datetime.strftime(pm_date_f1, '%Y-%#m-%#d')
#         ss_power_details = PowerMonitoring.objects.filter(o_id_id=current_org_id, e_id_id=e_id, pm_log_ts__startswith=pm_date_f2).values()
#         return render(request, 'ViewPowerMoniLogs.html', {"msg": ss_power_details})
#     else: # GET request
#         emp_details = Employee.objects.filter(o_id_id=current_org_id).values()
#         return render(request, 'SelectPowerMoniEmp.html', {"msg": emp_details})

@privileged_access_required
@permission_required('view_power_logs')
def power_monitoring(request):
    current_org_id = None
    if request.custom_user.is_org():
        current_org_id = request.custom_user.id
    elif request.custom_user.is_emp():
        current_org_id = request.custom_user.o_id_id
    
    if not current_org_id:
        messages.error(request, "Failed to determine organization context. Please re-authenticate.")
        return redirect('/LoginOrg')

    if request.method == 'POST':
        e_id = request.POST['e_id']
        pm_date = request.POST['date_log']
        
        pm_date_f1 = datetime.datetime.strptime(pm_date, '%Y-%m-%d')
        # FIX: Ensure YYYY-MM-DD format without platform-specific modifiers
        pm_date_f2 = pm_date_f1.strftime('%Y-%m-%d') # Changed from '%Y-%#m-%#d'

        # Debug prints
        print(f"DEBUG (power_monitoring): Filtering for e_id={e_id}, o_id={current_org_id}, date='{pm_date_f2}'")
        
        ss_power_details = PowerMonitoring.objects.filter(
            o_id_id=current_org_id,
            e_id_id=e_id,
            pm_log_ts__startswith=pm_date_f2
        ).values()

        print(f"DEBUG (power_monitoring): Found {len(ss_power_details)} records.")
        if ss_power_details:
            print(f"DEBUG (power_monitoring): First record pm_status: {ss_power_details[0]['pm_status']}, pm_log_ts: {ss_power_details[0]['pm_log_ts']}")

        return render(request, 'ViewPowerMoniLogs.html', {"msg": ss_power_details})
    else: # GET request
        emp_details = Employee.objects.filter(o_id_id=current_org_id).values()
        return render(request, 'SelectPowerMoniEmp.html', {"msg": emp_details})


# @user_login_required # Employee's own power logs, specific permission not required
# def user_power_monitoring(request):
#     current_org_id = request.custom_user.o_id_id
#     current_emp_id = request.custom_user.id

#     if request.method == 'POST':
#         pm_date = request.POST['date_log']
#         pm_date_f1 = datetime.datetime.strptime(pm_date, '%Y-%m-%d')
#         pm_date_f2 = datetime.datetime.strftime(pm_date_f1, '%Y-%#m-%#d')
#         ss_power_details = PowerMonitoring.objects.filter(o_id_id=current_org_id, e_id_id=current_emp_id, pm_log_ts__startswith=pm_date_f2).values()
#         return render(request, 'EmpViewPowerMoniLogs.html', {"msg": ss_power_details})
#     else:
#         return render(request, 'EmpSelectPowerMoniEmp.html')


@user_login_required
def user_power_monitoring(request):
    current_org_id = request.custom_user.o_id_id
    current_emp_id = request.custom_user.id

    if request.method == 'POST':
        pm_date = request.POST['date_log']
        
        pm_date_f1 = datetime.datetime.strptime(pm_date, '%Y-%m-%d')
        # FIX: Ensure YYYY-MM-DD format without platform-specific modifiers
        pm_date_f2 = pm_date_f1.strftime('%Y-%m-%d') # Changed from '%Y-%#m-%#d'

        # Debug prints
        print(f"DEBUG (user_power_monitoring): Filtering for e_id={current_emp_id}, o_id={current_org_id}, date='{pm_date_f2}'")
        
        ss_power_details = PowerMonitoring.objects.filter(
            o_id_id=current_org_id,
            e_id_id=current_emp_id,
            pm_log_ts__startswith=pm_date_f2
        ).values()

        print(f"DEBUG (user_power_monitoring): Found {len(ss_power_details)} records.")
        if ss_power_details:
            print(f"DEBUG (user_power_monitoring): First record pm_status: {ss_power_details[0]['pm_status']}, pm_log_ts: {ss_power_details[0]['pm_log_ts']}")

        return render(request, 'EmpViewPowerMoniLogs.html', {"msg": ss_power_details})
    else:
        return render(request, 'EmpSelectPowerMoniEmp.html')


@privileged_access_required
@permission_required('add_work_productivity_dataset')
def create_wp(request):
    current_org_id = None
    if request.custom_user.is_org():
        current_org_id = request.custom_user.id
    elif request.custom_user.is_emp():
        current_org_id = request.custom_user.o_id_id
    
    if not current_org_id:
        messages.error(request, "Failed to determine organization context. Please re-authenticate.")
        return redirect('/LoginOrg')

    if request.method == 'POST':
        wp_ds = request.POST['wp_ds']
        wp_type = request.POST['wp_type']
        wpObj = WorkProductivityDataset.objects.create(w_pds=wp_ds, w_type=wp_type, o_id_id=current_org_id)
        if wpObj:
            messages.success(request, "Work Productivity Dataset Entry was added successfully!")
            return HttpResponseRedirect('/create-wp')
        else:
            messages.error(request, "Some error was occurred!")
            return HttpResponseRedirect('/create-wp')
    return render(request, 'AddWorkProductivity.html')

@privileged_access_required
@permission_required('edit_work_productivity_dataset')
def read_edit_wp(request):
    current_org_id = None
    if request.custom_user.is_org():
        current_org_id = request.custom_user.id
    elif request.custom_user.is_emp():
        current_org_id = request.custom_user.o_id_id
    
    if not current_org_id:
        messages.error(request, "Failed to determine organization context. Please re-authenticate.")
        return redirect('/LoginOrg')

    wpds_details = WorkProductivityDataset.objects.filter(o_id_id=current_org_id).values()
    return render(request, 'EditWorkProductivity.html', {"msg": wpds_details})

@privileged_access_required
@permission_required('edit_meeting')
def edit_meet(request, mid):
    current_org_id = None
    if request.custom_user.is_org():
        current_org_id = request.custom_user.id
    elif request.custom_user.is_emp():
        current_org_id = request.custom_user.o_id_id
    
    if not current_org_id:
        messages.error(request, "Failed to determine organization context. Please re-authenticate.")
        return redirect('/LoginOrg')

    try:
        meet_details = Meeting.objects.filter(id=mid,o_id_id=current_org_id).first()
        if not meet_details:
            messages.error(request, "Meeting not found.")
            return HttpResponseRedirect('/read-meet')

        current_pid = meet_details.p_id_id
        current_project_name = Project.objects.filter(id=current_pid,o_id_id=current_org_id).values()[0]['p_name']
        project_names = Project.objects.filter(o_id_id=current_org_id).values_list('p_name', flat=True)
        pids = Project.objects.filter(o_id_id=current_org_id).values_list('id', flat=True)
        zipped_pid_pnames = zip(pids, project_names)

        if request.method == "POST":
            meet_name = request.POST['m_name']
            p_id = request.POST['p_id']
            start_date = request.POST['start_date']
            start_time = request.POST['start_time']
            meet_desc = request.POST['m_desc']

            meet_details.m_name = meet_name
            meet_details.p_id_id = p_id
            meet_details.m_start_date= start_date
            meet_details.m_start_time = start_time
            meet_details.m_desc = meet_desc
            meet_details.save()

            pel_details = Project_Employee_Linker.objects.filter(o_id_id=current_org_id,p_id_id=p_id).values_list('e_id_id', flat=True)
            user_details = Employee.objects.filter(id__in=pel_details).values()
            if user_details:
                for ud in user_details:
                    subject = 'MyRemoteDesk - Meeting Updated'
                    s_name = ud['e_name']
                    s_email = ud['e_email']
                    message = f'Hi, {s_name} A meeting has been updated! Details are Meeting Name :{meet_name}, Meeting Description: {meet_desc}, Date Time: {start_date} {start_time}. Check on MyRemoteDesk !'
                    email_from = settings.EMAIL_HOST_USER
                    recipient_list = [s_email]
                    send_mail(subject, message, email_from, recipient_list)
            messages.success(request,"Meeting Updated Successfully!")
            return HttpResponseRedirect('/read-meet')
        return render(request, 'UpdateMeeting.html', {'meet_details':meet_details, 'zipped_pid_pnames':zipped_pid_pnames, 'current_project_name':current_project_name})
    except Exception as e:
        messages.error(request, f"Some Error was occurred: {e}")
        return HttpResponseRedirect('/read-meet')

@privileged_access_required
@permission_required('delete_meeting')
def del_meet(request, mid):
    current_org_id = None
    if request.custom_user.is_org():
        current_org_id = request.custom_user.id
    elif request.custom_user.is_emp():
        current_org_id = request.custom_user.o_id_id
    
    if not current_org_id:
        messages.error(request, "Failed to determine organization context. Please re-authenticate.")
        return redirect('/LoginOrg')

    try:
        meet_details = Meeting.objects.filter(id=mid, o_id_id=current_org_id).delete()
        if meet_details[0] > 0:
            messages.success(request, "Meeting was deleted successfully!")
            return HttpResponseRedirect('/read-meet')
        else:
            messages.error(request, "Meeting not found or some error occurred!")
            return HttpResponseRedirect('/read-meet')
    except Exception as e:
        messages.error(request, f"Some Error was occurred: {e}")
        return HttpResponseRedirect('/read-meet')

@privileged_access_required
@permission_required('delete_work_productivity_dataset')
def del_wp(request, wid):
    current_org_id = None
    if request.custom_user.is_org():
        current_org_id = request.custom_user.id
    elif request.custom_user.is_emp():
        current_org_id = request.custom_user.o_id_id
    
    if not current_org_id:
        messages.error(request, "Failed to determine organization context. Please re-authenticate.")
        return redirect('/LoginOrg')

    try:
        wpds_details = WorkProductivityDataset.objects.filter(id=wid,o_id_id=current_org_id).delete()
        if wpds_details[0] > 0:
            messages.success(request, "Work Productivity Dataset Entry was deleted successfully!")
            return HttpResponseRedirect('/edit-wp')
        else:
            messages.error(request, "Dataset entry not found or some error occurred!")
            return HttpResponseRedirect('/edit-wp')
    except Exception as e:
        messages.error(request, f"Some Error was occurred: {e}")
        return HttpResponseRedirect('/edit-wp')

@privileged_access_required
@permission_required('create_task')
def create_task(request):
    current_org_id = None
    if request.custom_user.is_org():
        current_org_id = request.custom_user.id
    elif request.custom_user.is_emp():
        current_org_id = request.custom_user.o_id_id
    
    if not current_org_id:
        messages.error(request, "Failed to determine organization context. Please re-authenticate.")
        return redirect('/LoginOrg')

    boards = Board.objects.filter(o_id_id=current_org_id).values()
    projects = Project.objects.filter(o_id_id=current_org_id).values()
    employees = Employee.objects.filter(o_id_id=current_org_id).values() # This is a fallback if JS doesn't filter
    context = {"boards": boards, "projects": projects, "employees": employees}
    if request.method == 'POST':
        t_name = request.POST['t_name']
        t_desc = request.POST['t_desc']
        t_assign_date = request.POST['t_assign_date']
        t_deadline_date = request.POST['t_deadline_date']
        t_status = "todo"
        t_priority = request.POST['t_priority']
        b_id = request.POST['b_id']
        p_id = request.POST['p_id']
        e_id = request.POST['e_id']
        taskObj = Task.objects.create(t_name=t_name, t_desc=t_desc, t_assign_date=t_assign_date, t_deadline_date=t_deadline_date,
                                      t_status=t_status, t_priority=t_priority, o_id_id=current_org_id, b_id_id=b_id, p_id_id=p_id, e_id_id=e_id)
        if taskObj:
            empDetails = Employee.objects.filter(id=e_id, o_id_id=current_org_id).values()
            subject = 'MyRemoteDesk - New Task Created for you'
            message = f'Hi {empDetails[0]["e_name"]} , Your organization has created a new task : {t_name} , description : {t_desc}, priority : {t_priority} and deadline for task is : {t_deadline_date}, Login in your account to get more information. From: MyRemoteDesk. '
            email_from = settings.EMAIL_HOST_USER
            recipient_list = [empDetails[0]["e_email"], ]
            send_mail(subject, message, email_from, recipient_list)
            messages.success(request, "Task was created successfully!")
            return HttpResponseRedirect('/create-task')
        else:
            messages.error(request, "Some Error was occurred!")
            return HttpResponseRedirect('/create-task')
    return render(request, 'CreateTask.html', context)

@privileged_access_required
@permission_required('update_task')
def update_task(request, pk):
    current_org_id = None
    if request.custom_user.is_org():
        current_org_id = request.custom_user.id
    elif request.custom_user.is_emp():
        current_org_id = request.custom_user.o_id_id
    
    if not current_org_id:
        messages.error(request, "Failed to determine organization context. Please re-authenticate.")
        return redirect('/LoginOrg')

    try:
        tasks = get_object_or_404(Task, id=pk, o_id_id=current_org_id)
        p_id = tasks.p_id_id
        projects_emp_link = Project_Employee_Linker.objects.filter(o_id_id=current_org_id, p_id_id=p_id).all()
        if request.method == 'POST':
            t_name = request.POST['t_name']
            t_desc = request.POST['t_desc']
            t_deadline_date = request.POST['t_deadline_date']
            t_priority = request.POST['t_priority']
            e_id = request.POST['e_id']
            tasks.t_name = t_name
            tasks.t_desc = t_desc
            tasks.t_deadline_date = t_deadline_date
            tasks.t_priority = t_priority
            tasks.e_id_id = e_id
            tasks.save()
            if tasks:
                empDetails = Employee.objects.filter(id=e_id, o_id_id=current_org_id).values()
                subject = 'MyRemoteDesk - Task Updated for you'
                message = f'Hi {empDetails[0]["e_name"]} , Your organization has updated a task : {t_name} , description : {t_desc}, priority : {t_priority} and deadline for task is : {t_deadline_date}, Login in your account to get more information. From: MyRemoteDesk. '
                email_from = settings.EMAIL_HOST_USER
                recipient_list = [empDetails[0]["e_email"], ]
                send_mail(subject, message, email_from, recipient_list)
                messages.success(request, "Task was updated successfully!")
                return HttpResponseRedirect('/read-task')
            else:
                messages.error(request, "Some Error was occurred during update!")
                return HttpResponseRedirect('/read-task')
        else:
            return render(request, 'UpdateTask.html', {"tasks": tasks , "projects_emp_link": projects_emp_link } )
    except Exception as e:
        messages.error(request, f"Some Error was occurred: {e}")
        return HttpResponseRedirect('/read-task')

@privileged_access_required
@permission_required('view_task')
def read_tasks(request):
    current_org_id = None
    if request.custom_user.is_org():
        current_org_id = request.custom_user.id
    elif request.custom_user.is_emp():
        current_org_id = request.custom_user.o_id_id
    
    if not current_org_id:
        messages.error(request, "Failed to determine organization context. Please re-authenticate.")
        return redirect('/LoginOrg')

    board_details = Board.objects.filter(o_id_id=current_org_id).all()
    return render(request, 'ViewTasks.html', {"board_details": board_details})

@privileged_access_required
@permission_required('assign_project')
def get_emps_not_in_project(request, pid):
    current_org_id = None
    if request.custom_user.is_org():
        current_org_id = request.custom_user.id
    elif request.custom_user.is_emp():
        current_org_id = request.custom_user.o_id_id
    
    if not current_org_id:
        return JsonResponse({'error': 'Organization context missing.'}, status=400)

    if not Project.objects.filter(id=pid, o_id_id=current_org_id).exists():
        return JsonResponse({'error': 'Project not found for this organization.'}, status=404)

    eids_in_project = Project_Employee_Linker.objects.filter(p_id_id=pid, o_id_id=current_org_id).values_list('e_id_id', flat=True)
    unassigned_employees = Employee.objects.filter(o_id_id=current_org_id).exclude(id__in=eids_in_project)

    e_ids_names = [{'id': emp.id, 'name': emp.e_name.upper()} for emp in unassigned_employees]
    return JsonResponse(e_ids_names, safe=False)

@privileged_access_required
@permission_required('view_project_employees')
def get_emps_by_project(request, pid):
    current_org_id = None
    if request.custom_user.is_org():
        current_org_id = request.custom_user.id
    elif request.custom_user.is_emp():
        current_org_id = request.custom_user.o_id_id
    
    if not current_org_id:
        return JsonResponse({'error': 'Organization context missing.'}, status=400)

    if not Project.objects.filter(id=pid, o_id_id=current_org_id).exists():
        return JsonResponse({'error': 'Project not found for this organization.'}, status=404)

    # Corrected filter to use p_id_id for consistency with Django FK naming conventions
    eids_in_project = Project_Employee_Linker.objects.filter(p_id_id=pid, o_id_id=current_org_id).values_list('e_id_id', flat=True)
    employees_in_project = Employee.objects.filter(id__in=eids_in_project)

    e_ids_names = [{'id': emp.id, 'name': emp.e_name.upper()} for emp in employees_in_project]
    return JsonResponse(e_ids_names, safe=False)


@privileged_access_required
@permission_required('delete_task')
def delete_task(request, pk):
    current_org_id = None
    if request.custom_user.is_org():
        current_org_id = request.custom_user.id
    elif request.custom_user.is_emp():
        current_org_id = request.custom_user.o_id_id
    
    if not current_org_id:
        messages.error(request, "Failed to determine organization context. Please re-authenticate.")
        return redirect('/LoginOrg')

    try:
        tasks_deleted_count = Task.objects.filter(id=pk, o_id_id=current_org_id).delete()
        if tasks_deleted_count[0] > 0:
            messages.success(request, "Task was deleted successfully!")
            return HttpResponseRedirect('/read-task')
        else:
            messages.error(request, "Task not found or some error occurred!")
            return HttpResponseRedirect('/read-task')
    except Exception as e:
        messages.error(request, f"Some Error was occurred: {e}")
        return HttpResponseRedirect('/read-task')

@privileged_access_required
@permission_required('overview_tasks')
def overview_task(request):
    current_org_id = None
    if request.custom_user.is_org():
        current_org_id = request.custom_user.id
    elif request.custom_user.is_emp():
        current_org_id = request.custom_user.o_id_id
    
    if not current_org_id:
        messages.error(request, "Failed to determine organization context. Please re-authenticate.")
        return redirect('/LoginOrg')

    board_details = Board.objects.filter(o_id_id=current_org_id).all()
    org_board_names = list(Board.objects.filter(o_id_id=current_org_id).values_list('b_name',flat=True))
    if request.method == "POST":
        priority = request.POST['t_priority_filter']
        status = request.POST['t_status_filter']
        context = {"board_details": board_details, 'org_board_names':org_board_names, 'priority':priority, 'status':status}
        return render(request, 'OverviewTasks.html', context)
    else: # Initial GET request for the page
        context = {"board_details": board_details,'org_board_names':org_board_names, 'priority':'any', 'status':'any'}
        return render(request, 'OverviewTasks.html', context)

@user_login_required # Employee's own tasks overview, no specific permission needed
def user_overview_task(request):
    current_org_id = request.custom_user.o_id_id

    if request.method == "GET":
        board_details = Board.objects.filter(o_id_id=current_org_id).all()
        context = {"board_details": board_details}
        return render(request, 'EmpOverviewTasks.html', context)

@user_login_required # Employee's own projects, no specific permission needed
def user_view_projects(request):
    current_org_id = request.custom_user.o_id_id
    current_emp_id = request.custom_user.id

    if request.method == "GET":
        pel_details = Project_Employee_Linker.objects.filter(o_id_id=current_org_id, e_id_id=current_emp_id).values_list('p_id_id', flat=True)
        project_details = Project.objects.filter(id__in=pel_details).values()
        return render(request, 'EmpViewProj.html', {"msg": project_details})

@privileged_access_required
@permission_required('check_productivity')
def work_productivity_check(request):
    current_org_id = None
    if request.custom_user.is_org():
        current_org_id = request.custom_user.id
    elif request.custom_user.is_emp():
        current_org_id = request.custom_user.o_id_id
    
    if not current_org_id:
        messages.error(request, "Failed to determine organization context. Please re-authenticate.")
        return redirect('/LoginOrg')

    if request.method == 'POST':
        e_id = request.POST['e_id']
        m_date = request.POST['date_log']
        sum_of_emp_prod = get_work_productivity_details(current_org_id, e_id, m_date) # Pass current_org_id
        prd_total = 0
        unprd_total = 0
        undef_total = 0
        for i in sum_of_emp_prod:
            if i[1]==1:
                prd_total = prd_total+int(i[2])
            if i[1]==2:
                unprd_total = unprd_total+int(i[2])
            if i[1]==3:
                undef_total = undef_total+int(i[2])
        total_time_spent = prd_total + unprd_total +undef_total
        return render(request, 'ViewWorkProductivity.html', {"msg": sum_of_emp_prod, "msg1": prd_total, "msg2": e_id, "msg3": m_date, "msg4": unprd_total, "msg5": undef_total, "msg6": total_time_spent})
    else: # GET request
        emp_details = Employee.objects.filter(o_id_id=current_org_id).values()
        return render(request, 'SelectWpEmp.html', {"msg": emp_details})

@user_login_required # Employee's own productivity, no specific permission needed
def user_work_productivity_check(request):
    current_org_id = request.custom_user.o_id_id
    current_emp_id = request.custom_user.id

    if request.method == 'POST':
        m_date = request.POST['date_log']
        sum_of_emp_prod = get_work_productivity_details(current_org_id, current_emp_id, m_date) # Pass current_org_id and current_emp_id
        prd_total = 0
        unprd_total = 0
        undef_total = 0
        for i in sum_of_emp_prod:
            if i[1]==1:
                prd_total = prd_total+int(i[2])
            if i[1]==2:
                unprd_total = unprd_total+int(i[2])
            if i[1]==3:
                undef_total = undef_total+int(i[2])
        total_time_spent = prd_total + unprd_total +undef_total
        return render(request, 'EmpViewWorkProductivity.html', {"msg": sum_of_emp_prod, "msg1": prd_total, "msg2": current_emp_id, "msg3": m_date, "msg4": unprd_total, "msg5": undef_total, "msg6": total_time_spent})
    else:
        return render(request, 'EmpSelectWp.html')

@privileged_access_required
@permission_required('view_monitoring_piechart')
def logDashboard(request):
    current_org_id = None
    if request.custom_user.is_org():
        current_org_id = request.custom_user.id
    elif request.custom_user.is_emp():
        current_org_id = request.custom_user.o_id_id
    
    if not current_org_id:
        messages.error(request, "Failed to determine organization context. Please re-authenticate.")
        return redirect('/LoginOrg')

    employees = Employee.objects.filter(o_id_id=current_org_id).values()
    depth_moni_details = MonitoringDetails.objects.filter(o_id_id=current_org_id).values_list('md_title', 'md_total_time_seconds', 'md_date', 'e_id')
    app_names =  json.dumps([i[0] for i in depth_moni_details])
    app_usage_time =  json.dumps([i[1] for i in depth_moni_details])
    eids = json.dumps([i[3] for i in depth_moni_details])
    dates = json.dumps([i[2] for i in depth_moni_details])
    context = {'employees':employees,'app_usage_time':app_usage_time, 'app_names':app_names,'eids':eids, 'dates':dates}
    return render(request, 'logsDashboard.html', context)

# @privileged_access_required
# @permission_required('view_attendance')
# def org_view_attendance(request):
#     current_org_id = None
#     if request.custom_user.is_org():
#         current_org_id = request.custom_user.id
#     elif request.custom_user.is_emp():
#         current_org_id = request.custom_user.o_id_id
    
#     if not current_org_id:
#         messages.error(request, "Failed to determine organization context. Please re-authenticate.")
#         return redirect('/LoginOrg')

#     try:
#         emp_details = Employee.objects.filter(o_id_id=current_org_id).values()
#         if request.method=='POST':
#             e_id = request.POST['e_id']
#             m_date = request.POST['date_log']
#             m_date_f1 = datetime.datetime.strptime(m_date, '%Y-%m-%d')
#             m_date_f2 = datetime.datetime.strftime(m_date_f1, '%Y-%#m-%#d')

#             attendance_logs_query = AttendanceLogs.objects.filter(o_id_id=current_org_id, e_id_id=e_id,a_date=m_date_f2)

#             if not attendance_logs_query.exists():
#                 messages.error(request, "No attendance records found for the selected employee and date.")
#                 return render(request, 'Attendance.html', {"msg": emp_details})

#             attendance_logs = attendance_logs_query.values_list('a_date','a_ip_address','a_time_zone','a_lat','a_long').first()
#             logged_in_time_qs = attendance_logs_query.filter(a_status='1').values_list('a_time')
#             logged_out_time_qs = attendance_logs_query.filter(a_status='0').values_list('a_time')

#             logged_in_time = logged_in_time_qs.first()[0] if logged_in_time_qs.exists() else None
#             logged_out_time = logged_out_time_qs.first()[0] if logged_out_time_qs.exists() else None

#             if logged_in_time and logged_out_time:
#                 logged_in_dt = datetime.datetime.fromtimestamp(int(logged_in_time))
#                 logged_out_dt = datetime.datetime.fromtimestamp(int(logged_out_time))
#                 total_time_logged = logged_out_dt - logged_in_dt
#                 logged_in_time_formatted = logged_in_dt.strftime('%H:%M:%S')
#                 logged_out_time_formatted = logged_out_dt.strftime('%H:%M:%S')
#             else:
#                 total_time_logged = "N/A"
#                 logged_in_time_formatted = "N/A"
#                 logged_out_time_formatted = "N/A"

#             context = {
#                 "msg": emp_details,
#                 'attendance_logs': list(attendance_logs),
#                 'logged_in_time': logged_in_time_formatted,
#                 'logged_out_time': logged_out_time_formatted,
#                 'total_time_logged': total_time_logged
#             }
#             return render(request, 'Attendance.html', context)
#         else: # GET request
#             return render(request, 'Attendance.html', {"msg": emp_details})
#     except Exception as e:
#         messages.error(request,f"Data not found or some error was occurred: {e}")
#         return HttpResponseRedirect('/org-view-attendance')



@privileged_access_required
@permission_required('view_attendance')
def org_view_attendance(request):
    current_org_id = None
    if request.custom_user.is_org():
        current_org_id = request.custom_user.id
    elif request.custom_user.is_emp():
        current_org_id = request.custom_user.o_id_id
    
    if not current_org_id:
        messages.error(request, "Failed to determine organization context. Please re-authenticate.")
        return redirect('/LoginOrg')

    try:
        emp_details = Employee.objects.filter(o_id_id=current_org_id).values()
        if request.method=='POST':
            e_id = request.POST['e_id']
            m_date = request.POST['date_log']
            
            m_date_f1 = datetime.datetime.strptime(m_date, '%Y-%m-%d')
            # FIX: Ensure YYYY-MM-DD format without platform-specific modifiers
            m_date_f2 = m_date_f1.strftime('%Y-%m-%d') # Changed from '%Y-%#m-%#d'

            # Debug prints
            print(f"DEBUG (org_view_attendance): Filtering for e_id={e_id}, o_id={current_org_id}, date='{m_date_f2}'")

            # Note: a_date field in AttendanceLogs should be YYYY-MM-DD from Electron app
            attendance_logs_query = AttendanceLogs.objects.filter(o_id_id=current_org_id, e_id_id=e_id, a_date=m_date_f2)

            print(f"DEBUG (org_view_attendance): Found {attendance_logs_query.count()} attendance records for query.")

            if not attendance_logs_query.exists():
                messages.error(request, "No attendance records found for the selected employee and date.")
                return render(request, 'Attendance.html', {"msg": emp_details})

            # Since a_date is YYYY-MM-DD, a simple .first() on values_list for a_date, ip etc. is sufficient
            attendance_logs = attendance_logs_query.values_list('a_date','a_ip_address','a_time_zone','a_lat','a_long').first()
            logged_in_time_qs = attendance_logs_query.filter(a_status='1').values_list('a_time')
            logged_out_time_qs = attendance_logs_query.filter(a_status='0').values_list('a_time')

            logged_in_time = logged_in_time_qs.first()[0] if logged_in_time_qs.exists() else None
            logged_out_time = logged_out_time_qs.first()[0] if logged_out_time_qs.exists() else None

            if logged_in_time and logged_out_time:
                logged_in_dt = datetime.datetime.fromtimestamp(int(logged_in_time))
                logged_out_dt = datetime.datetime.fromtimestamp(int(logged_out_time))
                total_time_logged = logged_out_dt - logged_in_dt
                logged_in_time_formatted = logged_in_dt.strftime('%H:%M:%S')
                logged_out_time_formatted = logged_out_dt.strftime('%H:%M:%S')
            else:
                total_time_logged = "N/A"
                logged_in_time_formatted = "N/A"
                logged_out_time_formatted = "N/A"

            context = {
                "msg": emp_details,
                'attendance_logs': list(attendance_logs),
                'logged_in_time': logged_in_time_formatted,
                'logged_out_time': logged_out_time_formatted,
                'total_time_logged': total_time_logged
            }
            return render(request, 'Attendance.html', context)
        else: # GET request
            return render(request, 'Attendance.html', {"msg": emp_details})
    except Exception as e:
        messages.error(request,f"Data not found or some error was occurred: {e}")
        # This redirect might hide the root cause in some cases, consider removing it for debugging.
        return HttpResponseRedirect('/org-view-attendance')


# @user_login_required # Employee's own attendance, no specific permission needed
# def user_view_attendance(request):
#     current_emp_id = request.custom_user.id
#     current_org_id = request.custom_user.o_id_id

#     if request.method=='POST':
#         m_date = request.POST['date_log']
#         m_date_f1 = datetime.datetime.strptime(m_date, '%Y-%m-%d')
#         m_date_f2 = datetime.datetime.strftime(m_date_f1, '%Y-%#m-%#d')

#         attendance_logs_query = AttendanceLogs.objects.filter(e_id=current_emp_id, o_id_id=current_org_id, a_date=m_date_f2)

#         if not attendance_logs_query.exists():
#             messages.error(request, "No attendance records found for this date.")
#             return render(request, 'UserAttendance.html')

#         attendance_logs = attendance_logs_query.values_list('a_date','a_ip_address','a_time_zone','a_lat','a_long').first()
#         logged_in_time_qs = attendance_logs_query.filter(a_status='1').values_list('a_time')
#         logged_out_time_qs = attendance_logs_query.filter(a_status='0').values_list('a_time')

#         logged_in_time = logged_in_time_qs.first()[0] if logged_in_time_qs.exists() else None
#         logged_out_time = logged_out_time_qs.first()[0] if logged_out_time_qs.exists() else None

#         if logged_in_time and logged_out_time:
#             logged_in_dt = datetime.datetime.fromtimestamp(int(logged_in_time))
#             logged_out_dt = datetime.datetime.fromtimestamp(int(logged_out_time))
#             total_time_logged = logged_out_dt - logged_in_dt
#             logged_in_time_formatted = logged_in_dt.strftime('%H:%M:%S')
#             logged_out_time_formatted = logged_out_dt.strftime('%H:%M:%S')
#         else:
#             total_time_logged = "N/A"
#             logged_in_time_formatted = "N/A"
#             logged_out_time_formatted = "N/A"

#         context = {
#              'attendance_logs':list(attendance_logs),
#              'logged_in_time':logged_in_time_formatted,
#              'logged_out_time':logged_out_time_formatted,
#              'total_time_logged':total_time_logged
#         }
#         return render(request, 'UserAttendance.html', context)
#     return render(request, 'UserAttendance.html')


@user_login_required
def user_view_attendance(request):
    current_emp_id = request.custom_user.id
    current_org_id = request.custom_user.o_id_id

    if request.method=='POST':
        m_date = request.POST['date_log']
        
        m_date_f1 = datetime.datetime.strptime(m_date, '%Y-%m-%d')
        # FIX: Ensure YYYY-MM-DD format without platform-specific modifiers
        m_date_f2 = m_date_f1.strftime('%Y-%m-%d') # Changed from '%Y-%#m-%#d'

        # Debug prints
        print(f"DEBUG (user_view_attendance): Filtering for e_id={current_emp_id}, o_id={current_org_id}, date='{m_date_f2}'")

        attendance_logs_query = AttendanceLogs.objects.filter(e_id=current_emp_id, o_id_id=current_org_id, a_date=m_date_f2)

        print(f"DEBUG (user_view_attendance): Found {attendance_logs_query.count()} attendance records for query.")

        if not attendance_logs_query.exists():
            messages.error(request, "No attendance records found for this date.")
            return render(request, 'UserAttendance.html')

        attendance_logs = attendance_logs_query.values_list('a_date','a_ip_address','a_time_zone','a_lat','a_long').first()
        logged_in_time_qs = attendance_logs_query.filter(a_status='1').values_list('a_time')
        logged_out_time_qs = attendance_logs_query.filter(a_status='0').values_list('a_time')

        logged_in_time = logged_in_time_qs.first()[0] if logged_in_time_qs.exists() else None
        logged_out_time = logged_out_time_qs.first()[0] if logged_out_time_qs.exists() else None

        if logged_in_time and logged_out_time:
            logged_in_dt = datetime.datetime.fromtimestamp(int(logged_in_time))
            logged_out_dt = datetime.datetime.fromtimestamp(int(logged_out_time))
            total_time_logged = logged_out_dt - logged_in_dt
            logged_in_time_formatted = logged_in_dt.strftime('%H:%M:%S')
            logged_out_time_formatted = logged_out_dt.strftime('%H:%M:%S')
        else:
            total_time_logged = "N/A"
            logged_in_time_formatted = "N/A"
            logged_out_time_formatted = "N/A"

        context = {
             'attendance_logs':list(attendance_logs),
             'logged_in_time':logged_in_time_formatted,
             'logged_out_time':logged_out_time_formatted,
             'total_time_logged':total_time_logged
        }
        return render(request, 'UserAttendance.html', context)
    return render(request, 'UserAttendance.html')

@privileged_access_required
@permission_required('unassign_employee_from_project')
def select_unassign(request):
    current_org_id = None
    if request.custom_user.is_org():
        current_org_id = request.custom_user.id
    elif request.custom_user.is_emp():
        current_org_id = request.custom_user.o_id_id
    
    if not current_org_id:
        messages.error(request, "Failed to determine organization context. Please re-authenticate.")
        return redirect('/LoginOrg')

    project_details = Project.objects.filter(o_id_id=current_org_id).values()
    return render(request, 'unassign.html', {"msg": project_details})

@privileged_access_required
@permission_required('unassign_employee_from_project')
def unassign_employee(request):
    current_org_id = None
    if request.custom_user.is_org():
        current_org_id = request.custom_user.id
    elif request.custom_user.is_emp():
        current_org_id = request.custom_user.o_id_id
    
    if not current_org_id:
        messages.error(request, "Failed to determine organization context. Please re-authenticate.")
        return redirect('/LoginOrg')

    if request.method == 'POST':
        pid = request.POST['p_id']
    else:
        messages.error(request, "Invalid request for unassigning employee.")
        return redirect('select-unassign')

    pname = Project.objects.filter(id=pid, o_id_id=current_org_id).values_list('p_name',flat=True).first()
    if not pname:
        messages.error(request, "Project not found or not accessible.")
        return redirect('select-unassign')

    proj_emp_ids = Project_Employee_Linker.objects.filter(o_id_id=current_org_id, p_id_id=pid).values_list('e_id_id', flat=True)
    emp_details = list(Employee.objects.filter(id__in=proj_emp_ids).values())

    return render(request, 'unassignemp.html', {"msg": emp_details, 'pname':pname, 'pid':pid})

@privileged_access_required
@permission_required('unassign_employee_from_project')
def unassign_emp(request, eid):
    current_org_id = None
    if request.custom_user.is_org():
        current_org_id = request.custom_user.id
    elif request.custom_user.is_emp():
        current_org_id = request.custom_user.o_id_id
    
    if not current_org_id:
        messages.error(request, "Failed to determine organization context. Please re-authenticate.")
        return redirect('/LoginOrg')

    if request.method == 'POST':
        pid = request.POST['p_id']
        emp_detail = Project_Employee_Linker.objects.filter(o_id_id=current_org_id, e_id_id=eid, p_id_id=pid).delete()
        if emp_detail[0] > 0:
            messages.success(request, "Employee unassigned from project successfully!")
        else:
            messages.error(request, "Failed to unassign employee or employee not found in project.")
        return redirect('unassign-employee') # Redirect to the selection page after action
    else:
        messages.error(request, "Invalid request.")
        return redirect('unassign-employee') # Redirect to the selection page if not POST

@privileged_access_required
@permission_required('create_notice')
def create_notice(request):
    current_org_id = None
    if request.custom_user.is_org():
        current_org_id = request.custom_user.id
    elif request.custom_user.is_emp():
        current_org_id = request.custom_user.o_id_id
    
    if not current_org_id:
        messages.error(request, "Failed to determine organization context. Please re-authenticate.")
        return redirect('/LoginOrg')

    if request.method == 'POST':
        on_title = request.POST['on_title']
        on_desc = request.POST['on_desc']
        noticeObj = OrganizationNews.objects.create(on_title=on_title, on_desc=on_desc, o_id_id=current_org_id)
        if noticeObj:
            user_details = Employee.objects.filter(o_id_id=current_org_id).values()
            if user_details:
                for ud in user_details:
                    subject = 'MyRemoteDesk - New Notice Published'
                    s_name = ud['e_name']
                    s_email = ud['e_email']
                    message = f'Hi, {s_name} Your Organization has published a new notice, Notice Title: {on_title} Check on MyRemoteDesk !'
                    email_from = settings.EMAIL_HOST_USER
                    recipient_list = [s_email]
                    send_mail(subject, message, email_from, recipient_list)
            messages.success(request,"Notice was created successfully!")
            return HttpResponseRedirect('/create-notice')
        else:
            messages.error(request, "Some Error was occurred!")
            return HttpResponseRedirect('/create-notice')
    return render(request, 'CreateNotice.html' )

@privileged_access_required
@permission_required('view_notice')
def read_notices(request):
    current_org_id = None
    if request.custom_user.is_org():
        current_org_id = request.custom_user.id
    elif request.custom_user.is_emp():
        current_org_id = request.custom_user.o_id_id
    
    if not current_org_id:
        messages.error(request, "Failed to determine organization context. Please re-authenticate.")
        return redirect('/LoginOrg')

    noticeObj = OrganizationNews.objects.filter(o_id_id=current_org_id).values()
    return render(request, 'ViewNotices.html', {"notices": noticeObj})

@privileged_access_required
@permission_required('update_notice')
def update_notice(request, pk):
    current_org_id = None
    if request.custom_user.is_org():
        current_org_id = request.custom_user.id
    elif request.custom_user.is_emp():
        current_org_id = request.custom_user.o_id_id
    
    if not current_org_id:
        messages.error(request, "Failed to determine organization context. Please re-authenticate.")
        return redirect('/LoginOrg')

    try:
        noticeObj = get_object_or_404(OrganizationNews, id=pk,o_id_id=current_org_id)
        if request.method == 'POST':
            noticeObj.on_title = request.POST['on_title']
            noticeObj.on_desc = request.POST['on_desc']
            noticeObj.save()
            messages.success(request, "Notice was updated successfully!")
            return HttpResponseRedirect('/read-notice')
        else:
            return render(request, 'UpdateNotice.html', {"noticeObj": noticeObj })
    except Exception as e:
        messages.error(request, f"Some Error was occurred: {e}")
        return HttpResponseRedirect('/read-notice')

@privileged_access_required
@permission_required('overview_notice')
def overview_notices(request):
    current_org_id = None
    if request.custom_user.is_org():
        current_org_id = request.custom_user.id
    elif request.custom_user.is_emp():
        current_org_id = request.custom_user.o_id_id
    
    if not current_org_id:
        messages.error(request, "Failed to determine organization context. Please re-authenticate.")
        return redirect('/LoginOrg')

    noticeObj = OrganizationNews.objects.filter(o_id_id=current_org_id).all()
    return render(request, 'OverviewNotices.html', {"notices": noticeObj})

@privileged_access_required
@permission_required('delete_notice')
def delete_notice(request, pk):
    current_org_id = None
    if request.custom_user.is_org():
        current_org_id = request.custom_user.id
    elif request.custom_user.is_emp():
        current_org_id = request.custom_user.o_id_id
    
    if not current_org_id:
        messages.error(request, "Failed to determine organization context. Please re-authenticate.")
        return redirect('/LoginOrg')

    try:
        noticeObj_deleted_count = OrganizationNews.objects.filter(id=pk,o_id_id=current_org_id).delete()
        if noticeObj_deleted_count[0] > 0:
            messages.success(request, "Notice was deleted successfully!")
            return HttpResponseRedirect('/read-notice')
        else:
            messages.error(request, "Notice not found or some error occurred!")
            return HttpResponseRedirect('/read-notice')
    except Exception as e:
        messages.error(request, f"Some Error was occurred: {e}")
        return HttpResponseRedirect('/read-notice')

@privileged_access_required
@permission_required('apply_for_leave')
def user_apply_emp_leaves(request):
    current_emp_id = request.custom_user.id
    current_org_id = request.custom_user.o_id_id

    if not current_org_id: # Should not happen if @privileged_access_required is working
        messages.error(request, "Failed to determine organization context. Please re-authenticate.")
        return redirect('/LoginOrg')

    if request.method == 'POST':
        l_reason = request.POST['l_reason']
        l_desc = request.POST['l_desc']
        l_start_date = request.POST['l_start_date']
        l_no_of_leaves = request.POST['l_no_of_leaves']
        l_status = "Assigned"
        LeaveObj = Leaves.objects.create( l_reason=l_reason, l_desc=l_desc, l_start_date=l_start_date, l_no_of_leaves=l_no_of_leaves, l_status=l_status, o_id_id=current_org_id, e_id_id=current_emp_id)
        if LeaveObj:
            messages.success(request, "Leave Request was created successfully!")
            return HttpResponseRedirect('/user-apply-emp-leaves')
        else:
            messages.error(request, "Some Error was occurred!")
            return HttpResponseRedirect('/user-apply-emp-leaves')
    else:
        return render(request, 'UserApplyEmpLeaves.html')

@user_login_required # Employee's own leaves, no specific permission needed
def user_view_emp_leaves(request):
    current_org_id = request.custom_user.o_id_id
    current_emp_id = request.custom_user.id

    LeaveObj = Leaves.objects.filter(o_id_id=current_org_id, e_id_id=current_emp_id).all()
    context = {"leaves": LeaveObj}
    return render(request, 'UserViewEmpLeaves.html' , context)

@privileged_access_required
@permission_required('manage_employee_leaves')
def org_emp_leave_views(request):
    current_org_id = None
    if request.custom_user.is_org():
        current_org_id = request.custom_user.id
    elif request.custom_user.is_emp():
        current_org_id = request.custom_user.o_id_id
    
    if not current_org_id:
        messages.error(request, "Failed to determine organization context. Please re-authenticate.")
        return redirect('/LoginOrg')

    LeaveObj = Leaves.objects.filter(o_id_id=current_org_id,l_status="Assigned").all()
    return render(request, 'OrgEmpLeavesTbl.html' , {"leaves": LeaveObj})

@privileged_access_required
@permission_required('manage_employee_leaves')
def org_emp_leave_approval(request, pk):
    current_org_id = None
    if request.custom_user.is_org():
        current_org_id = request.custom_user.id
    elif request.custom_user.is_emp():
        current_org_id = request.custom_user.o_id_id
    
    if not current_org_id:
        messages.error(request, "Failed to determine organization context. Please re-authenticate.")
        return redirect('/LoginOrg')

    LeaveInd = get_object_or_404(Leaves, id=pk, o_id_id=current_org_id)
    if request.method == 'POST':
        LeaveInd.l_status = request.POST['l_status']
        LeaveInd.save()
        messages.success(request, "Leave Request Approved/Rejected Successfully")
        return HttpResponseRedirect('/emp-leaves')
    else:
        # If this function is accessed via GET (e.g., direct URL), redirect back
        return HttpResponseRedirect('/emp-leaves')

@user_login_required # Employee's own tasks, specific permission not required (since they're already assigned)
def emp_view_tasks(request):
    current_org_id = request.custom_user.o_id_id

    if request.method == 'GET':
        board_details = Board.objects.filter(o_id_id=current_org_id).all()
        context = {"board_details": board_details}
        return render(request, 'EmpViewTask.html', context)

@privileged_access_required
@permission_required('update_my_tasks')
def emp_update_tasks(request, tid):
    current_org_id = request.custom_user.o_id_id
    current_emp_id = request.custom_user.id

    t_update_date = datetime.datetime.today().strftime('%Y-%m-%d')
    task_updated_count = Task.objects.filter(id=tid, o_id_id=current_org_id, e_id_id=current_emp_id).update(t_update_date=t_update_date, t_status="completed")
    if task_updated_count > 0:
        messages.success(request, "Task Marked as completed!")
        return HttpResponseRedirect('/emp-view-tasks')
    else:
        messages.error(request, "Task not found or some error was occurred!")
        return HttpResponseRedirect('/emp-view-tasks')

@user_login_required # Employee viewing notices, no specific permission needed
def emp_view_notices(request):
    current_org_id = request.custom_user.o_id_id

    noticeObj = OrganizationNews.objects.filter(o_id_id=current_org_id).order_by('-id').all()
    context = {"notices": noticeObj}
    return render(request, 'EmpNotices.html', context)

# Helper function for productivity details, takes o_id and e_id as arguments
def get_work_productivity_details(o_id, e_id, m_date):
        md_date_f1 = datetime.datetime.strptime(m_date, '%Y-%m-%d')
        md_date_f2 = datetime.datetime.strftime(md_date_f1, '%Y-%#m-%#d')
        sum_of_emp_prod = []

        wp_ds_pr_details_unclean = list(WorkProductivityDataset.objects.filter(
            o_id_id=o_id, w_type='1').values_list('w_pds'))
        wp_ds_un_pr_details_unclean = list(WorkProductivityDataset.objects.filter(
            o_id_id=o_id, w_type='0').values_list('w_pds'))
        emp_work_data_details_unclean = list(MonitoringDetails.objects.filter(
            o_id_id=o_id, e_id_id=e_id, md_date=md_date_f2).values_list('md_title', 'md_total_time_seconds').distinct())

        wp_ds_pr_details = [
            item for x in wp_ds_pr_details_unclean for item in x]
        wp_ds_un_pr_details = [
            item for x in wp_ds_un_pr_details_unclean for item in x]

        categorized_data = {}
        for emp_title, time_spent in emp_work_data_details_unclean:
            category_found = False
            for pr in wp_ds_pr_details:
                if fuzz.partial_ratio(emp_title, pr) >= 60:
                    categorized_data[emp_title] = (1, time_spent)
                    category_found = True
                    break
            if category_found:
                continue

            for un_pr in wp_ds_un_pr_details:
                if fuzz.partial_ratio(emp_title, un_pr) >= 60:
                    categorized_data[emp_title] = (2, time_spent)
                    category_found = True
                    break
            if category_found:
                continue

            if emp_title not in categorized_data:
                 categorized_data[emp_title] = (3, time_spent)

        sum_of_emp_prod = [(title, type_val, time_val) for title, (type_val, time_val) in categorized_data.items()]
        return sum_of_emp_prod

@privileged_access_required
@permission_required('check_productivity')
def get_prod_details(request, eidanddate):
    parts = eidanddate.split('and')
    if len(parts) != 3:
        return JsonResponse({'error': 'Invalid request format.'}, status=400)

    e_id = parts[0]
    m_date = parts[1]
    o_id = parts[2] # This o_id comes from the AJAX request, not request.custom_user directly

    try:
        e_id = int(e_id)
        o_id = int(o_id)
    except ValueError:
        return JsonResponse({'error': 'Invalid ID format.'}, status=400)

    # Re-verify the organization context from custom_user for an extra layer of security
    # to ensure the requesting user has access to this organization's data.
    requesting_user_org_id = None
    if request.custom_user.is_org():
        requesting_user_org_id = request.custom_user.id
    elif request.custom_user.is_emp():
        requesting_user_org_id = request.custom_user.o_id_id
    
    if not requesting_user_org_id or requesting_user_org_id != o_id:
        return JsonResponse({'error': 'Unauthorized access to organization data.'}, status=403)

    if not Employee.objects.filter(id=e_id, o_id_id=o_id).exists():
        return JsonResponse({'error': 'Employee not found for this organization.'}, status=404)

    sum_of_emp_prod = get_work_productivity_details(o_id, e_id, m_date)
    prd_total = 0
    unprd_total = 0
    undef_total = 0
    for title, category, time_spent_str in sum_of_emp_prod:
        try:
            time_spent = int(time_spent_str)
        except ValueError:
            continue

        if category == 1:
            prd_total += time_spent
        elif category == 2:
            unprd_total += time_spent
        elif category == 3:
            undef_total += time_spent

    titles = ['prd_total', 'unprd_total', 'undef_total']
    values = [prd_total, unprd_total, undef_total]
    total_dict = dict(zip(titles, values))
    return JsonResponse(total_dict)

@privileged_access_required
@permission_required('view_project_employees')
def view_project_wise_employees(request):
    current_org_id = None
    if request.custom_user.is_org():
        current_org_id = request.custom_user.id
    elif request.custom_user.is_emp():
        current_org_id = request.custom_user.o_id_id
    
    if not current_org_id:
        messages.error(request, "Failed to determine organization context. Please re-authenticate.")
        return redirect('/LoginOrg')

    projects = Project.objects.filter(o_id_id=current_org_id)
    projEmps = {}
    for project in projects:
        linked_employees = Employee.objects.filter(
            project_employee_linker__p_id=project,
            project_employee_linker__o_id_id=current_org_id
        ).values_list('e_name', flat=True)
        projEmps[project.p_name] = list(linked_employees)

    return render(request, 'ViewProjEmps.html', {'projEmps':projEmps})

@privileged_access_required
@permission_required('rank_employees_productivity')
def rank_productivity(request):
    current_org_id = None
    if request.custom_user.is_org():
        current_org_id = request.custom_user.id
    elif request.custom_user.is_emp():
        current_org_id = request.custom_user.o_id_id
    
    if not current_org_id:
        messages.error(request, "Failed to determine organization context. Please re-authenticate.")
        return redirect('/LoginOrg')

    employees = Employee.objects.filter(o_id_id=current_org_id)

    all_emps_taskwise_scores = []
    all_emps_only_prd_score = []
    enames = []

    for emp in employees:
        enames.append(emp.e_name)
        overall_prod_details = get_overall_work_productivity_details(current_org_id, emp.id)
        current_emp_prd_total = sum(int(item[2]) for item in overall_prod_details if item[1] == 1)
        all_emps_only_prd_score.append(current_emp_prd_total)

        # Ensure correct FK access for Task.objects.filter (e_id_id and o_id_id)
        submission_dates = list(Task.objects.filter(o_id_id=current_org_id, e_id_id=emp.id, t_status="completed").values_list('t_update_date', flat=True))
        deadline_dates = list(Task.objects.filter(o_id_id=current_org_id, e_id_id=emp.id, t_status="completed").values_list('t_deadline_date', flat=True))

        current_emp_taskwise_scores = []
        for s,d in zip(submission_dates, deadline_dates):
            if s is not None and d is not None:
                try:
                    s_date = datetime.datetime.strptime(s, '%Y-%m-%d')
                    d_date = datetime.datetime.strptime(d, '%Y-%m-%d')
                    time_diff = d_date - s_date
                    days_diff = time_diff.days
                    if days_diff >= 0:
                        current_emp_taskwise_scores.append(days_diff)
                    else:
                        current_emp_taskwise_scores.append(0)
                except ValueError:
                    current_emp_taskwise_scores.append(0)
            else:
                current_emp_taskwise_scores.append(0)

        all_emps_taskwise_scores.append(sum(current_emp_taskwise_scores))

    all_emps_total_productivity_score = []
    total_sum_for_normalization = 0
    for task_score, prod_score in zip(all_emps_taskwise_scores, all_emps_only_prd_score):
        combined_score = prod_score + (task_score * 60 * 60) # Convert days diff to seconds for score
        all_emps_total_productivity_score.append(combined_score)
        total_sum_for_normalization += combined_score

    if total_sum_for_normalization > 0:
        all_emps_total_productivity_score = [round((i / total_sum_for_normalization) * 100, 4) for i in all_emps_total_productivity_score]
    else:
        all_emps_total_productivity_score = [0 for _ in all_emps_total_productivity_score]

    all_emps_total_productivity_score_dict = dict(zip(enames, all_emps_total_productivity_score))
    all_emps_total_productivity_score_dict = dict(sorted(all_emps_total_productivity_score_dict.items(), key=lambda item: item[1], reverse=True))

    emp_name = list(all_emps_total_productivity_score_dict.keys())
    emp_score = list(all_emps_total_productivity_score_dict.values())

    data = [go.Bar(
        x=emp_name,
        y=emp_score
    )]
    fig = go.Figure(data=data)
    plot_div = plot(fig, output_type='div')
    return render(request, 'productivityRanks.html', {'all_emps_only_prd_score_dict':all_emps_total_productivity_score_dict, 'plot_div':plot_div})

# Helper function
def get_overall_work_productivity_details(o_id, e_id):
        sum_of_emp_prod = []

        wp_ds_pr_details_unclean = list(WorkProductivityDataset.objects.filter(
            o_id_id=o_id, w_type='1').values_list('w_pds'))
        wp_ds_un_pr_details_unclean = list(WorkProductivityDataset.objects.filter(
            o_id_id=o_id, w_type='0').values_list('w_pds'))
        emp_work_data_details_unclean = list(MonitoringDetails.objects.filter(
            o_id_id=o_id, e_id_id=e_id).values_list('md_title', 'md_total_time_seconds'))

        wp_ds_pr_details = [
            item for x in wp_ds_pr_details_unclean for item in x]
        wp_ds_un_pr_details = [
            item for x in wp_ds_un_pr_details_unclean for item in x]

        categorized_data = {}
        for emp_title, time_spent in emp_work_data_details_unclean:
            category_found = False
            for pr in wp_ds_pr_details:
                if fuzz.partial_ratio(emp_title, pr) >= 70:
                    categorized_data[emp_title] = (1, time_spent)
                    category_found = True
                    break
            if category_found:
                continue

            for un_pr in wp_ds_un_pr_details:
                if fuzz.partial_ratio(emp_title, un_pr) >= 70:
                    categorized_data[emp_title] = (2, time_spent)
                    category_found = True
                    break
            if category_found:
                continue

            if emp_title not in categorized_data:
                 categorized_data[emp_title] = (3, time_spent)

        sum_of_emp_prod = [(title, type_val, time_val) for title, (type_val, time_val) in categorized_data.items()]
        return sum_of_emp_prod

# Helper function
def get_only_prod_details(oid, eid):
    o_id = oid
    e_id = eid
    sum_of_emp_prod = get_overall_work_productivity_details(o_id, e_id)
    prd_total = 0
    prd_total = sum(int(i[2]) for i in sum_of_emp_prod if i[1] == 1)
    return prd_total

@privileged_access_required
@permission_required('view_active_employees_count')
def get_emp_logged_in_count_today(request):
    current_org_id = None
    if request.custom_user.is_org():
        current_org_id = request.custom_user.id
    elif request.custom_user.is_emp():
        current_org_id = request.custom_user.o_id_id
    
    if not current_org_id:
        return JsonResponse({'error': 'Organization context missing or unauthorized.'}, status=403) # Return 403 for API calls

    total_emps = Employee.objects.filter(o_id_id=current_org_id).count()
    today_date_str = datetime.datetime.today().strftime('%Y-%#m-%#d')
    logged_in_count = AttendanceLogs.objects.filter(o_id_id=current_org_id, a_date=today_date_str, a_status='1').count()

    return JsonResponse({'total_emps':total_emps, 'logged_in_count':logged_in_count})

# Removed @csrf_exempt for security; CSRF token should be handled by form templates
def logout(request):
    if request.method == 'POST':
        try:
            # If custom_user has a logout method (e.g. for custom session management), call it.
            # In your case, CustomUserMiddleware sets is_authenticated = True and handles proxy.
            # The core of logout is flushing the session.
            # if hasattr(request, 'custom_user') and hasattr(request.custom_user, 'logout'):
            #     request.custom_user.logout() # This part of CustomUserProxy is just an indicator

            for key in list(request.session.keys()):
                del request.session[key]
            messages.success(request, "You are logged out successfully!")
            return HttpResponseRedirect('/')
        except Exception as e:
            messages.error(request, f"Some error occurred during logout: {e}")
            return HttpResponseRedirect('/')
