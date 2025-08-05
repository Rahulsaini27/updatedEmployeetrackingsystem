# app/decorators.py
from functools import wraps
from django.shortcuts import redirect
from django.contrib import messages
# from app.models import Employee, Organization # Not strictly needed here, CustomUserProxy abstracts it

def privileged_access_required(view_func):
    """
    Decorator for views that requires a user to be authenticated and
    either an Organization admin, or an Employee who has an assigned role
    and that role has at least one permission.
    """
    @wraps(view_func)
    def _wrapped_view(request, *args, **kwargs):
        # Ensure custom_user exists from middleware
        if not hasattr(request, 'custom_user'):
            messages.error(request, "Authentication system error. Please log in.")
            return redirect('/LoginOrg') # Fallback to Org login if middleware fails

        custom_user = request.custom_user

        # 1. Check if user is authenticated at all
        if not custom_user.is_authenticated:
            messages.error(request, "Please log in to access this page.")
            # Redirect to appropriate login page based on session hint, or default to Org login
            if request.session.get('u_type') == 'emp':
                return redirect('/LoginUser')
            else:
                return redirect('/LoginOrg')

        # 2. User is authenticated, now check access level based on type
        if custom_user.is_org():
            # Organization users are implicitly super-admins and pass this general access check
            return view_func(request, *args, **kwargs)
        
        elif custom_user.is_emp():
            # For employees, access the underlying Employee object to check role and its permissions
            employee_obj = custom_user._user_obj 
            
            # Check if the employee has an assigned role
            if not employee_obj.role:
                messages.error(request, "Your account has no assigned role and thus no access to privileged features. Please contact your administrator.")
                return redirect('/user_index') # Redirect employee to their dashboard

            # Check if the assigned role has *any* permissions
            # This relies on the 'permissions' ManyToManyField on the Role model
            if not employee_obj.role.permissions.exists():
                messages.error(request, f"Your role '{employee_obj.role.name}' has no permissions assigned and thus no access to privileged features. Please contact your administrator.")
                return redirect('/user_index') # Redirect employee to their dashboard

            # If an employee has a role with at least one permission, grant access
            return view_func(request, *args, **kwargs)
        else:
            # Fallback for unexpected user types (should ideally not be hit with your middleware setup)
            messages.error(request, "Access denied: unrecognized user type.")
            return redirect('/') # Generic homepage

    return _wrapped_view

def permission_required(perm_codename):
    """
    Decorator for views that checks if the request.custom_user has a specific permission.
    This decorator can be used after `privileged_access_required` for layered checks,
    or standalone if the view's basic authentication is handled elsewhere.
    """
    def decorator(view_func):
        @wraps(view_func)
        def _wrapped_view(request, *args, **kwargs):
            # This block provides a fallback for authentication if `privileged_access_required`
            # or `org_login_required`/`user_login_required` isn't applied before it.
            # For robust multi-decorator usage, it's safer to keep this check.
            if not hasattr(request, 'custom_user') or not request.custom_user.is_authenticated:
                messages.error(request, "Please log in to access this page.")
                if request.session.get('u_type') == 'emp':
                    return redirect('/LoginUser')
                else:
                    return redirect('/LoginOrg')

            if not request.custom_user.has_perm(perm_codename):
                messages.error(request, f"You do not have permission to access this feature: '{perm_codename}'.")
                # Redirect to a generic dashboard or homepage based on user type
                if request.custom_user.user_type == 'emp':
                    return redirect('/user_index')
                else:
                    return redirect('/org_index')
            return view_func(request, *args, **kwargs)
        return _wrapped_view
    return decorator

# Your existing login_required decorators remain for specific cases where
# only session type is the primary check, without granular permission needs.
# For views where RBAC permissions are used, you'll generally replace them.