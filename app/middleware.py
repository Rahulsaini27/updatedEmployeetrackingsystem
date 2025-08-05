from app.models import Employee, Organization, Role, Permission
import functools

class CustomUserMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.session.get('logged_in'):
            user_type = request.session.get('u_type')

            class ProxyUser:
                def __init__(self, user_obj, user_type):
                    self._user_obj = user_obj
                    self.user_type = user_type
                    self.is_authenticated = True # Indicate a logged-in user

                def __getattr__(self, name):
                    """Delegate attribute access to the underlying user object."""
                    return getattr(self._user_obj, name)

                def has_perm(self, perm_codename):
                    """
                    Checks if the current user has the specified permission.
                    For Employees: Checks their assigned role's permissions.
                    For Organizations: Assumed to have all permissions (admin equivalent).
                    """
                    if self.user_type == 'org':
                        # Organization users are implicitly super-admins for their org
                        return True
                    elif self.user_type == 'emp':
                        employee = self._user_obj
                        if employee.role:
                            # Check if the permission exists in the employee's role's permissions
                            return employee.role.permissions.filter(codename=perm_codename).exists()
                    return False # No role or permission not found

                def is_org(self):
                    return self.user_type == 'org'

                def is_emp(self):
                    return self.user_type == 'emp'

            if user_type == 'emp':
                try:
                    employee_id = request.session.get('u_id')
                    employee = Employee.objects.select_related('role').get(id=employee_id)
                    request.custom_user = ProxyUser(employee, 'emp')
                except Employee.DoesNotExist:
                    request.custom_user = None # User not found, invalidate session
                    request.session.flush() # Clear invalid session
            elif user_type == 'org':
                try:
                    org_id = request.session.get('o_id')
                    organization = Organization.objects.get(id=org_id)
                    request.custom_user = ProxyUser(organization, 'org')
                except Organization.DoesNotExist:
                    request.custom_user = None # User not found, invalidate session
                    request.session.flush() # Clear invalid session
            else:
                request.custom_user = None
        else:
            # For unauthenticated users, provide a default object to avoid errors
            class AnonymousUserProxy:
                is_authenticated = False
                user_type = None
                def has_perm(self, perm_codename):
                    return False
                def is_org(self): return False
                def is_emp(self): return False
            request.custom_user = AnonymousUserProxy()


        response = self.get_response(request)
        return response