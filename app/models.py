from django.db import models
from datetime import datetime
from django.conf import settings # Ensure settings is imported for potential future use

# Create your models here.

class Organization(models.Model):
    o_name = models.CharField(max_length=100)
    o_email = models.EmailField()
    o_password = models.CharField(max_length=32)
    o_contact = models.CharField(max_length=100)
    o_website = models.CharField(max_length=100)
    o_address = models.CharField(max_length=150)

    def __str__(self):
        return f'{self.o_email} {self.o_password}'

    class Meta:
        db_table = "organization"

# class Employee(models.Model):
#     o_id = models.ForeignKey(Organization, on_delete=models.CASCADE)
#     e_name = models.CharField(max_length=100)
#     e_email = models.EmailField()
#     e_password = models.CharField(max_length=32)
#     e_gender = models.CharField(max_length=25)
#     e_contact = models.CharField(max_length=100)
#     e_address = models.CharField(max_length=150)

#     def __str__(self):
#         return f'{self.id} {self.e_email} {self.e_password} {self.e_address} {self.e_contact} {self.e_gender}'

#     class Meta:
#         db_table = "employee"


# adding new feature


class Permission(models.Model):
    """
    Represents a specific permission that can be granted to a role.
    e.g., 'view_logs', 'approve_leave', 'create_task'.
    """
    codename = models.CharField(
        max_length=100,
        unique=True,
        help_text="A unique code for the permission (e.g., 'view_logs')"
    )
    name = models.CharField(
        max_length=255,
        help_text="A human-readable name for the permission"
    )
    description = models.TextField(
        blank=True,
        null=True,
        help_text="Optional description of the permission"
    )

    def __str__(self):
        return f"{self.name} ({self.codename})"

    class Meta:
        db_table = "permission"
        ordering = ['name']

class Role(models.Model):
    """
    Represents a role that can be assigned to employees.
    Each role has a set of permissions.
    """
    name = models.CharField(
        max_length=100,
        unique=True,
        help_text="The name of the role (e.g., 'Manager', 'Developer')"
    )
    description = models.TextField(
        blank=True,
        null=True,
        help_text="Optional description of the role"
    )
    permissions = models.ManyToManyField(
        Permission,
        related_name='roles',
        blank=True, # Allows creating roles without assigning permissions initially
        help_text="Permissions assigned to this role"
    )

    def __str__(self):
        return self.name

    class Meta:
        db_table = "role"
        ordering = ['name']

class Employee(models.Model):
    # ... (your existing fields: o_id, e_name, e_email, e_password, e_gender, e_contact, e_address)
    o_id = models.ForeignKey(Organization, on_delete=models.CASCADE)
    e_name = models.CharField(max_length=100)
    e_email = models.EmailField()
    e_password = models.CharField(max_length=32)
    e_gender = models.CharField(max_length=25)
    e_contact = models.CharField(max_length=100)
    e_address = models.CharField(max_length=150)

    # --- RBAC ADDITION ---
    role = models.ForeignKey(
        Role,
        on_delete=models.SET_NULL, # If a role is deleted, employee's role becomes None
        null=True,
        blank=True, # Role is optional until assigned
        related_name='employees',
        help_text="The role assigned to this employee"
    )
    # --- END RBAC ADDITION ---

    def __str__(self):
        return f'{self.e_name} ({self.e_email})'

    class Meta:
        db_table = "employee"
        
# ending new feature

class Project(models.Model):
    p_name = models.CharField(max_length=100)
    p_desc = models.CharField(max_length=200)
    o_id = models.ForeignKey(Organization, on_delete=models.CASCADE)

    class Meta:
        db_table = "project"

class Board(models.Model):
    b_name = models.CharField(max_length=100)
    o_id = models.ForeignKey(Organization, on_delete=models.CASCADE)

    class Meta:
        db_table = "board"


class Task(models.Model):
    t_name = models.CharField(max_length=55)
    t_desc = models.CharField(max_length=200)
    t_status = models.CharField(max_length=55)
    t_priority = models.CharField(max_length=30)
    t_assign_date = models.CharField(max_length=55)
    t_deadline_date = models.CharField(max_length=55)
    t_update_date = models.CharField(max_length=55, null=True)
    b_id = models.ForeignKey(Board, on_delete=models.CASCADE, related_name='boardids')
    p_id = models.ForeignKey(Project, on_delete=models.CASCADE, related_name='projectids')
    o_id = models.ForeignKey(Organization, on_delete=models.CASCADE)
    e_id = models.ForeignKey(Employee, on_delete=models.CASCADE, related_name='employeeids')
    
    class Meta:
        db_table = "task"



class Monitoring(models.Model):
    m_title = models.CharField(max_length=200, null=True)
    m_log_ts = models.CharField(max_length=200)
    e_id = models.ForeignKey(Employee, on_delete=models.CASCADE)
    o_id = models.ForeignKey(Organization, on_delete=models.CASCADE)

    class Meta:
        db_table = "monitoring"

class MonitoringDetails(models.Model):
    md_title = models.CharField(max_length=200)
    md_total_time_seconds = models.CharField(max_length=200)
    md_date = models.CharField(max_length=200)
    e_id = models.ForeignKey(Employee, on_delete=models.CASCADE)
    o_id = models.ForeignKey(Organization, on_delete=models.CASCADE)

    class Meta:
        db_table = "MonitoringDetails"

class ScreenShotsMonitoring(models.Model):
    ssm_img = models.TextField(max_length=255)
    ssm_log_ts = models.CharField(max_length=200)
    e_id = models.ForeignKey(Employee, on_delete=models.CASCADE)
    o_id = models.ForeignKey(Organization, on_delete=models.CASCADE)

    class Meta:
        db_table = "ScreenShotsMonitoring"

class PowerMonitoring(models.Model):
    pm_status = models.CharField(max_length=255)
    pm_log_ts = models.CharField(max_length=200)
    e_id = models.ForeignKey(Employee, on_delete=models.CASCADE)
    o_id = models.ForeignKey(Organization, on_delete=models.CASCADE)

    class Meta:
        db_table = "PowerMonitoring"

class Meeting(models.Model):
    m_name = models.CharField(max_length=55)
    m_desc = models.CharField(max_length=200)
    m_uuid = models.CharField(max_length=200)
    m_start_date = models.CharField(max_length=55)
    m_stop_date = models.CharField(max_length=55)
    m_start_time = models.CharField(max_length=55)
    m_stop_time = models.CharField(max_length=55)
    p_id = models.ForeignKey(Project, on_delete=models.CASCADE)
    o_id = models.ForeignKey(Organization, on_delete=models.CASCADE)

    class Meta:
        db_table = "meeting"

class Project_Employee_Linker(models.Model):
    p_id = models.ForeignKey(Project, on_delete=models.CASCADE)
    e_id = models.ForeignKey(Employee, on_delete=models.CASCADE)
    o_id = models.ForeignKey(Organization, on_delete=models.CASCADE)

    class Meta:
        unique_together = ('p_id', 'e_id','o_id')
        db_table = "project_emp_assign"


class WorkProductivityDataset(models.Model):
    w_pds = models.CharField(max_length=255)
    w_type = models.CharField(max_length=255)
    o_id = models.ForeignKey(Organization, on_delete=models.CASCADE)

    class Meta:
        db_table = "WorkProductivityDataset"


class OrganizationNews(models.Model):
    on_title = models.CharField(max_length=255)
    on_desc = models.TextField(max_length=255)
    on_date_time = models.DateTimeField(auto_now=True)
    o_id = models.ForeignKey(Organization, on_delete=models.CASCADE)

    class Meta:
        db_table = "OrganizationNews"


class AttendanceLogs(models.Model):
    a_date = models.CharField(max_length=55)
    a_time = models.CharField(max_length=55)
    a_status = models.CharField(max_length=55)
    a_ip_address = models.CharField(max_length=55)
    a_time_zone = models.CharField(max_length=55)
    a_lat = models.CharField(max_length=55)
    a_long = models.CharField(max_length=55)
    e_id = models.ForeignKey(Employee, on_delete=models.CASCADE)
    o_id = models.ForeignKey(Organization, on_delete=models.CASCADE)

    class Meta:
        db_table = "AttendanceLogs"


class Leaves(models.Model):
    l_reason = models.CharField(max_length=55)
    l_desc = models.CharField(max_length=200)
    l_start_date = models.CharField(max_length=55)
    l_no_of_leaves = models.PositiveIntegerField()
    l_status = models.CharField(max_length=55)
    e_id = models.ForeignKey(Employee, on_delete=models.CASCADE)
    o_id = models.ForeignKey(Organization, on_delete=models.CASCADE)

    class Meta:
        db_table = "leaves"
