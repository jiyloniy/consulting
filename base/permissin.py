from rest_framework import permissions

class ReadORAuditPermission(permissions.BasePermission):
    """
    Custom permission to only allow read or audit actions.
    """

    def has_permission(self, request, view):
        if view.action in ['list', 'retrieve']:
            return True
        return request.user and request.user.is_authenticated
    
# Post on the forum

class PostAndAuhtorPermission(permissions.BasePermission):
    """
    Custom permission to only allow read or audit actions.
    """

    def has_permission(self, request, view):
        if view.action in ['create']:
            return True
        return request.user and request.user.is_authenticated
