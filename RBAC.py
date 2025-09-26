# === Simple RBAC Implementation ===

class RBAC:
    def __init__(self):
        self.roles = {}        # role -> set of permissions
        self.users = {}        # user -> set of roles

    def add_role(self, role):
        if role not in self.roles:
            self.roles[role] = set()

    def add_permission_to_role(self, role, permission):
        if role in self.roles:
            self.roles[role].add(permission)

    def assign_role_to_user(self, user, role):
        if user not in self.users:
            self.users[user] = set()
        if role in self.roles:
            self.users[user].add(role)

    def check_access(self, user, permission):
        """Return True if user has permission via any role"""
        if user not in self.users:
            return False
        for role in self.users[user]:
            if permission in self.roles.get(role, []):
                return True
        return False


# === Demo ===
if __name__ == "__main__":
    rbac = RBAC()

    # Define roles
    rbac.add_role("admin")
    rbac.add_role("editor")
    rbac.add_role("viewer")

    # Assign permissions to roles
    rbac.add_permission_to_role("admin", "delete_post")
    rbac.add_permission_to_role("admin", "edit_post")
    rbac.add_permission_to_role("admin", "view_post")

    rbac.add_permission_to_role("editor", "edit_post")
    rbac.add_permission_to_role("editor", "view_post")

    rbac.add_permission_to_role("viewer", "view_post")

    # Assign users to roles
    rbac.assign_role_to_user("alice", "admin")
    rbac.assign_role_to_user("bob", "editor")
    rbac.assign_role_to_user("charlie", "viewer")

    # Check access
    print("Alice delete_post:", rbac.check_access("alice", "delete_post"))   # True
    print("Bob delete_post:", rbac.check_access("bob", "delete_post"))       # False
    print("Charlie view_post:", rbac.check_access("charlie", "view_post"))   # True
    print("Charlie edit_post:", rbac.check_access("charlie", "edit_post"))   # False
