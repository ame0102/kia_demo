from django.urls import path
from . import views

urlpatterns = [
    # Insecure API endpoints
    path('insecure/auth/', views.insecure_auth, name='insecure_auth'),
    path('insecure/vin_lookup/', views.insecure_vin_lookup, name='insecure_vin_lookup'),
    path('insecure/demote_owner/', views.insecure_demote_owner, name='insecure_demote_owner'),
    path('insecure/add_owner/', views.insecure_add_owner, name='insecure_add_owner'),
    path('insecure/firmware/download/', views.insecure_firmware_download, name='insecure_firmware_download'),
    path('insecure/can/send/', views.insecure_can_send, name='insecure_can_send'),
    
    # Secure API endpoints
    path('secure/auth/', views.secure_auth, name='secure_auth'),
    path('secure/vin_lookup/', views.secure_vin_lookup, name='secure_vin_lookup'),
    path('secure/demote_owner/', views.secure_demote_owner, name='secure_demote_owner'),
    path('secure/add_owner/', views.secure_add_owner, name='secure_add_owner'),
    path('secure/firmware/download/', views.secure_firmware_download, name='secure_firmware_download'),
    path('secure/can/send/', views.secure_can_send, name='secure_can_send'),
    
    # Simulation endpoints
    path('logs/', views.get_security_logs, name='security_logs'),
    path('simulate_attack/', views.simulate_attack, name='simulate_attack'),
    path('reset_simulation/', views.reset_simulation, name='reset_simulation'),
]