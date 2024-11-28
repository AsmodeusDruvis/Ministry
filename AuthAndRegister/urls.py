from django.urls import path
from .views import UserVoidSignupView , UserVoidLoginView , UserVoidLogoutView , UserVoidSoftDeleteView, UserVoidHardDeleteView , PasswordChangeView , UserVoidEditView

#Url pathways to hell

urlpatterns = [
    path('signup/', UserVoidSignupView.as_view(), name='user-signup'),
    path('login/', UserVoidLoginView.as_view(), name='user-login'),
    path('logout/', UserVoidLogoutView.as_view(), name='user-logout'),
    path('soft-delete-account/', UserVoidSoftDeleteView.as_view(), name='soft-delete-account'),
    path('hard-delete-account/', UserVoidHardDeleteView.as_view(), name='hard-delete-account'),
    path('password-change/', PasswordChangeView.as_view(), name='password_change'),
    path('auth/edit/', UserVoidEditView.as_view(), name='user-edit'),
]
