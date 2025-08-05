from django.core.management.base import BaseCommand
from app.models import Permission, Role

class Command(BaseCommand):
    help = 'Creates initial permissions and roles for the application and assigns permissions to roles.'

    def handle(self, *args, **options):
        self.stdout.write(self.style.SUCCESS('Starting creation of permissions and roles...'))

        # 1. Define all possible permissions with codenames and names/descriptions
        permissions_data = [
            # Employee Management
            {'codename': 'add_employee', 'name': 'Add Employee', 'description': 'Allows adding new employees.'},
            {'codename': 'view_employee', 'name': 'View Employee', 'description': 'Allows viewing employee details (all).'},
            {'codename': 'update_employee', 'name': 'Update Employee', 'description': 'Allows updating employee details.'},
            {'codename': 'delete_employee', 'name': 'Delete Employee', 'description': 'Allows deleting employees.'},
            {'codename': 'view_my_profile', 'name': 'View My Profile', 'description': 'Allows an employee to view their own profile.'},

            # Board Management
            {'codename': 'create_board', 'name': 'Create Board', 'description': 'Allows creating new Kanban boards.'},
            {'codename': 'view_board', 'name': 'View Board', 'description': 'Allows viewing Kanban board details.'},
            {'codename': 'delete_board', 'name': 'Delete Board', 'description': 'Allows deleting Kanban boards.'},

            # Project Management
            {'codename': 'create_project', 'name': 'Create Project', 'description': 'Allows creating new projects.'},
            {'codename': 'view_project', 'name': 'View Project', 'description': 'Allows viewing project details (all).'},
            {'codename': 'delete_project', 'name': 'Delete Project', 'description': 'Allows deleting projects.'},
            {'codename': 'assign_project', 'name': 'Assign Project to Employee', 'description': 'Allows assigning employees to projects.'},
            {'codename': 'unassign_employee_from_project', 'name': 'Unassign Employee from Project', 'description': 'Allows unassigning employees from projects.'},
            {'codename': 'view_project_employees', 'name': 'View Project Employees', 'description': 'Allows viewing employees assigned to specific projects.'},
            {'codename': 'view_my_projects', 'name': 'View My Projects', 'description': 'Allows an employee to view projects they are assigned to.'},

            # Task Management
            {'codename': 'create_task', 'name': 'Create Task', 'description': 'Allows creating new tasks.'},
            {'codename': 'view_task', 'name': 'View Task', 'description': 'Allows viewing all tasks (org user).'},
            {'codename': 'update_task', 'name': 'Update Task', 'description': 'Allows updating tasks.'},
            {'codename': 'delete_task', 'name': 'Delete Task', 'description': 'Allows deleting tasks.'},
            {'codename': 'overview_tasks', 'name': 'Overview Tasks', 'description': 'Allows viewing an overview of all tasks (Kanban board) for the organization.'},
            {'codename': 'view_project_tasks', 'name': 'View Project Tasks', 'description': 'Allows viewing tasks within a specific project (org user).'},
            {'codename': 'view_board_tasks', 'name': 'View Board Tasks', 'description': 'Allows viewing tasks within a specific board (org user).'},
            {'codename': 'view_my_tasks', 'name': 'View My Tasks', 'description': 'Allows an employee to view tasks assigned to them.'},
            {'codename': 'update_my_tasks', 'name': 'Update My Tasks', 'description': 'Allows an employee to update the status of their own tasks (e.g., mark as complete).'},
            {'codename': 'view_my_tasks_overview', 'name': 'View My Tasks Overview', 'description': 'Allows an employee to view an overview of their own tasks (Kanban style).'},
            {'codename': 'view_my_project_tasks', 'name': 'View My Project Tasks', 'description': 'Allows an employee to view tasks assigned to them within a project (their own projects).'},

            # Meeting Management
            {'codename': 'create_meeting', 'name': 'Create Meeting', 'description': 'Allows creating new meetings.'},
            {'codename': 'view_meeting', 'name': 'View Meeting', 'description': 'Allows viewing all meeting details (org user).'},
            {'codename': 'edit_meeting', 'name': 'Edit Meeting', 'description': 'Allows editing meeting details.'},
            {'codename': 'delete_meeting', 'name': 'Delete Meeting', 'description': 'Allows deleting meetings.'},
            {'codename': 'view_my_meeting', 'name': 'View My Meetings', 'description': 'Allows an employee to view meetings they are part of.'},

            # Productivity Monitoring & Analysis (Org-level)
            {'codename': 'add_work_productivity_dataset', 'name': 'Add Work Productivity Dataset', 'description': 'Allows adding apps/websites to the productivity dataset.'},
            {'codename': 'edit_work_productivity_dataset', 'name': 'Edit Work Productivity Dataset', 'description': 'Allows viewing and editing work productivity dataset entries.'},
            {'codename': 'delete_work_productivity_dataset', 'name': 'Delete Work Productivity Dataset', 'description': 'Allows deleting work productivity dataset entries.'},
            {'codename': 'check_productivity', 'name': 'Check Employee Productivity', 'description': 'Allows checking productivity reports of all employees.'},
            {'codename': 'rank_employees_productivity', 'name': 'Rank Employees Productivity', 'description': 'Allows ranking employees based on productivity scores.'},
            {'codename': 'view_monitoring_piechart', 'name': 'View Monitoring PieChart', 'description': 'Allows viewing visual summaries (pie charts) of app usage.'},

            # Detailed Monitoring Logs (Org-level)
            {'codename': 'view_app_web_logs', 'name': 'View App/Web Logs', 'description': 'Allows viewing general app/web usage logs for all employees.'},
            {'codename': 'view_detailed_app_web_logs', 'name': 'View Detailed App/Web Logs', 'description': 'Allows viewing detailed app/web usage logs (time spent per app/site) for all employees.'},
            {'codename': 'view_screenshots', 'name': 'View Screenshots', 'description': 'Allows viewing screenshots captured from employee desktops.'},
            {'codename': 'view_power_logs', 'name': 'View Power Logs', 'description': 'Allows viewing power state logs for employees (e.g., sleep, shutdown).'},
            {'codename': 'view_active_employees_count', 'name': 'View Active Employees Count', 'description': 'Allows viewing the count of currently active employees on the dashboard.'},

            # Detailed Monitoring Logs (Employee-level)
            {'codename': 'view_my_app_web_logs', 'name': 'View My App/Web Logs', 'description': 'Allows an employee to view their own app/web usage logs.'},
            {'codename': 'view_my_detailed_app_web_logs', 'name': 'View My Detailed App/Web Logs', 'description': 'Allows an employee to view their own detailed app/web usage logs.'},
            {'codename': 'view_my_screenshots', 'name': 'View My Screenshots', 'description': 'Allows an employee to view their own captured screenshots.'},
            {'codename': 'view_my_power_logs', 'name': 'View My Power Logs', 'description': 'Allows an employee to view their own power state logs.'},
            {'codename': 'check_my_productivity', 'name': 'Check My Productivity', 'description': 'Allows an employee to check their own productivity report.'},


            # Notices
            {'codename': 'create_notice', 'name': 'Create Notice', 'description': 'Allows creating new organizational notices.'},
            {'codename': 'view_notice', 'name': 'View Notice', 'description': 'Allows viewing all organizational notices (org user).'},
            {'codename': 'update_notice', 'name': 'Update Notice', 'description': 'Allows updating organizational notices.'},
            {'codename': 'delete_notice', 'name': 'Delete Notice', 'description': 'Allows deleting organizational notices.'},
            {'codename': 'overview_notice', 'name': 'Overview Notices', 'description': 'Allows viewing a summary of notices.'},
            {'codename': 'view_employee_notices', 'name': 'View Employee Notices', 'description': 'Allows an employee to view notices relevant to them.'},

            # Leaves
            {'codename': 'apply_for_leave', 'name': 'Apply for Leave', 'description': 'Allows employees to submit leave requests.'},
            {'codename': 'view_my_leaves', 'name': 'View My Leaves', 'description': 'Allows an employee to view the status of their own leave requests.'},
            {'codename': 'manage_employee_leaves', 'name': 'Manage Employee Leaves', 'description': 'Allows approving or rejecting employee leave requests.'},

            # Attendance
            {'codename': 'view_attendance', 'name': 'View Attendance', 'description': 'Allows viewing attendance records for all employees.'},
            {'codename': 'view_my_attendance', 'name': 'View My Attendance', 'description': 'Allows an employee to view their own attendance records.'},

            # System & User Settings
            {'codename': 'report_problems', 'name': 'Report Problems', 'description': 'Allows users to report issues or give suggestions.'},
            {'codename': 'change_password', 'name': 'Change Password', 'description': 'Allows users to change their own password.'},

            # RBAC Management
            {'codename': 'create_role', 'name': 'Create Role', 'description': 'Allows creating new roles.'},
            {'codename': 'view_role', 'name': 'View Role', 'description': 'Allows viewing existing roles.'},
            {'codename': 'update_role', 'name': 'Update Role', 'description': 'Allows updating existing roles.'},
            {'codename': 'delete_role', 'name': 'Delete Role', 'description': 'Allows deleting roles.'},
            {'codename': 'create_permission', 'name': 'Create Permission', 'description': 'Allows creating new permissions.'},
            {'codename': 'view_permission', 'name': 'View Permission', 'description': 'Allows viewing existing permissions.'},
            {'codename': 'update_permission', 'name': 'Update Permission', 'description': 'Allows updating existing permissions.'},
            {'codename': 'delete_permission', 'name': 'Delete Permission', 'description': 'Allows deleting permissions.'},
        ]

        # Create/Update Permissions
        for perm_data in permissions_data:
            Permission.objects.get_or_create(
                codename=perm_data['codename'],
                defaults={'name': perm_data['name'], 'description': perm_data['description']}
            )
            self.stdout.write(self.style.SUCCESS(f"Permission '{perm_data['name']}' created/updated."))

        self.stdout.write(self.style.SUCCESS('\nAll permissions processed.'))
        self.stdout.write(self.style.SUCCESS('Starting creation and assignment of roles...'))

        # Get all created permissions for easy assignment
        all_permissions = {p.codename: p for p in Permission.objects.all()}

        # 2. Define roles and assign permissions (using the codenames defined above)
        roles_data = {
            'SuperAdmin': {
                'description': 'Highest level of administrative access with full control over all system features and configurations, including RBAC.',
                'permissions': [p['codename'] for p in permissions_data] # SuperAdmin gets ALL permissions
            },
            'Admin': {
                'description': 'Full administrative access to all functional features, but may have limited access to critical RBAC configurations (e.g., cannot delete SuperAdmin role or modify core permissions).',
                'permissions': [
                    # Employee Management
                    'add_employee', 'view_employee', 'update_employee', 'delete_employee',
                    # Board Management
                    'create_board', 'view_board', 'delete_board',
                    # Project Management
                    'create_project', 'view_project', 'delete_project', 'assign_project', 'unassign_employee_from_project', 'view_project_employees',
                    # Task Management
                    'create_task', 'view_task', 'update_task', 'delete_task', 'overview_tasks', 'view_project_tasks', 'view_board_tasks',
                    # Meeting Management
                    'create_meeting', 'view_meeting', 'edit_meeting', 'delete_meeting',
                    # Productivity Monitoring & Analysis (Org-level)
                    'add_work_productivity_dataset', 'edit_work_productivity_dataset', 'delete_work_productivity_dataset', 'check_productivity', 'rank_employees_productivity', 'view_monitoring_piechart',
                    # Detailed Monitoring Logs (Org-level)
                    'view_app_web_logs', 'view_detailed_app_web_logs', 'view_screenshots', 'view_power_logs', 'view_active_employees_count',
                    # Notices
                    'create_notice', 'view_notice', 'update_notice', 'delete_notice', 'overview_notice',
                    # Leaves
                    'manage_employee_leaves',
                    # Attendance
                    'view_attendance',
                    # System & User Settings
                    'report_problems', 'change_password',
                    # RBAC Management (Admin can manage roles and permissions but might be restricted from deleting the SuperAdmin role or critical permissions)
                    'create_role', 'view_role', 'update_role', 'delete_role',
                    'create_permission', 'view_permission', 'update_permission', 'delete_permission',
                ]
            },
            'HR': {
                'description': 'Manages employee records, leaves, attendance, and general organizational communication.',
                'permissions': [
                    'add_employee', 'view_employee', 'update_employee', 'delete_employee',
                    'manage_employee_leaves', 'view_attendance',
                    'create_notice', 'view_notice', 'update_notice', 'delete_notice', 'overview_notice',
                    'report_problems', 'change_password',
                    'view_role', 'view_permission', # HR can view RBAC structures but not manage them fully
                    'check_productivity', 'rank_employees_productivity', # Can view productivity reports
                    'view_app_web_logs', 'view_detailed_app_web_logs', 'view_screenshots', 'view_power_logs', # Can view general logs
                    'add_work_productivity_dataset', 'edit_work_productivity_dataset', 'delete_work_productivity_dataset', # Manage productivity dataset
                ]
            },
            'HR Trainee': {
                'description': 'Assists HR with basic tasks, primarily focused on viewing employee information and reports.',
                'permissions': [
                    'view_employee', 'view_attendance', 'view_notice', 'overview_notice',
                    'view_my_profile', 'change_password', 'report_problems', # Personal permissions
                ]
            },
            'Manager': {
                'description': 'Oversees projects, assigns tasks, manages teams within projects, and tracks progress. Can view team\'s productivity and logs.',
                'permissions': [
                    'view_employee', # Can view basic employee details
                    'view_project', 'create_project', 'assign_project', 'unassign_employee_from_project', 'view_project_employees',
                    'create_board', 'view_board',
                    'create_task', 'view_task', 'update_task', 'overview_tasks', 'view_project_tasks', 'view_board_tasks',
                    'create_meeting', 'view_meeting', 'edit_meeting',
                    'check_productivity', 'rank_employees_productivity', # Can check own team's productivity
                    'view_app_web_logs', 'view_detailed_app_web_logs', 'view_screenshots', 'view_power_logs', # Can view team's logs
                    'view_notice', 'overview_notice', # Can view notices
                    'view_attendance', # Can view team's attendance
                    'report_problems', 'change_password',
                ]
            },
            'Employee': {
                'description': 'Standard employee access with focus on personal profile, assigned tasks, own monitoring logs, and general communication.',
                'permissions': [
                    'view_my_profile', 'change_password', 'report_problems',
                    'view_employee_notices', # Can see notices from org
                    'view_my_meeting',
                    'view_my_app_web_logs', 'view_my_detailed_app_web_logs', 'view_my_screenshots', 'view_my_power_logs',
                    'check_my_productivity',
                    'view_my_projects', 'view_my_project_tasks', 'view_my_tasks_overview', 'view_my_tasks', 'update_my_tasks', # Can manage own tasks
                    'view_my_attendance', 'apply_for_leave', 'view_my_leaves', # Can manage own leaves/attendance
                ]
            },
            'Intern': {
                'description': 'Limited access for interns, mainly focused on personal tasks, basic communication, and self-monitoring.',
                'permissions': [
                    'view_my_profile', 'change_password', 'report_problems',
                    'view_employee_notices',
                    'view_my_tasks', 'update_my_tasks', 'view_my_tasks_overview',
                    'view_my_attendance',
                    'view_my_app_web_logs', 'view_my_detailed_app_web_logs',
                    'check_my_productivity',
                ]
            },
        }

        # Create/Update Roles and Assign Permissions
        for role_name, role_details in roles_data.items():
            role, created = Role.objects.get_or_create(
                name=role_name,
                defaults={'description': role_details.get('description', '')}
            )
            if not created:
                # If role already exists, update its description (if provided)
                if 'description' in role_details:
                    role.description = role_details['description']
                    role.save()
            self.stdout.write(self.style.SUCCESS(f"Role '{role_name}' created/updated."))

            # Assign permissions to the role
            # First, get all permission objects for the current role
            current_permissions_for_role = []
            for codename in role_details['permissions']:
                # Ensure the permission actually exists before trying to add it
                perm = all_permissions.get(codename)
                if perm:
                    current_permissions_for_role.append(perm)
                else:
                    self.stdout.write(self.style.WARNING(f"   Permission '{codename}' not found in defined permissions for role '{role_name}'."))

            # Use .set() to replace all existing permissions with the new set
            # This makes the command idempotent for permission assignments
            role.permissions.set(current_permissions_for_role)
            self.stdout.write(self.style.SUCCESS(f"   Permissions assigned to role '{role_name}'."))

        self.stdout.write(self.style.SUCCESS('\nInitial permissions and roles created and assigned successfully!'))