from django.urls import path  # Import views module
from django.conf import settings
from django.conf.urls.static import static
from .import views
from .views import (
    home, payment_process_view, payment_status_view,
    user_register, user_login, user_logout, payment_callback,
    payment_success_view  # Ensure you import the success view
)
from django.contrib.auth import views as auth_views

urlpatterns = [
    path('', home, name='home'),
    path('payment/', views.payment, name='payment'),
    path('payment/process/', payment_process_view, name='process_payment'),
    path('payment/status/', payment_status_view, name='payment_status'),
    path('payment/callback/', payment_callback, name='payment_callback'),
    path('payment/success/', payment_success_view, name='success'),  # Define the success URL pattern
    path('register/', user_register, name='register'),
    path('login/', user_login, name='login'),
    path('logout/', user_logout, name='logout'),
    path('payment/error/', views.payment_error_view, name='payment_error'), 
    path('password_reset/', views.password_reset, name='password_reset'),
    path('password_reset/done/', auth_views.PasswordResetDoneView.as_view(template_name='password_reset_done.html'), name='password_reset_done'),
    path('reset/<uidb64>/<token>/', views.password_reset_confirm, name='password_reset_confirm'),
    path('reset/done/', auth_views.PasswordResetCompleteView.as_view(template_name='password_reset_complete.html'), name='password_reset_complete'),
    # Add other URL patterns as needed
]
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
