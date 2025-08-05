from django import template

register = template.Library()

@register.filter
def has_perm(user, perm_codename):
    """
    Checks if a custom_user object has a specific permission.
    Assumes request.custom_user is available and has a .has_perm() method.
    """
    if not hasattr(user, 'has_perm') or not user.is_authenticated:
        return False
    return user.has_perm(perm_codename)

@register.filter
def is_org(user):
    """
    Checks if the custom_user object represents an organization.
    """
    if not hasattr(user, 'is_org'):
        return False
    return user.is_org()

@register.filter
def is_emp(user):
    """
    Checks if the custom_user object represents an employee.
    """
    if not hasattr(user, 'is_emp'):
        return False
    return user.is_emp()