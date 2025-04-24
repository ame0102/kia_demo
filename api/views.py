import json
import time
import jwt
import hmac
import hashlib
import os
from pathlib import Path
from datetime import datetime, timedelta

from django.http import JsonResponse, FileResponse
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth import authenticate
from django.conf import settings
from rest_framework.decorators import api_view
from rest_framework.response import Response

from .models import Vehicle, FirmwareVersion, SecurityLog

# Create directory for keys if it doesn't exist
KEYS_DIR = Path(settings.BASE_DIR) / 'keys'
KEYS_DIR.mkdir(exist_ok=True)

# Generate JWT keys if they don't exist
JWT_KEY_PATH = KEYS_DIR / 'jwt_key.pem'
if not JWT_KEY_PATH.exists():
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization
    
    # Generate RSA key pair
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    
    # Save private key
    with open(JWT_KEY_PATH, 'wb') as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    
    # Save public key
    with open(KEYS_DIR / 'jwt_key.pub', 'wb') as f:
        f.write(private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

# Read JWT key
with open(JWT_KEY_PATH, 'rb') as f:
    JWT_KEY = f.read()

# CAN bus key for CMAC
CAN_KEY = b"VehicleSecurityKey"

# Static session ID for insecure API
INSECURE_SID = "insecure-sid-0001"

# Helper functions
def log_security_event(event_type, description, vehicle=None, user=None, success=True, request=None):
    """Log security events to the database"""
    ip = None
    if request:
        ip = request.META.get('REMOTE_ADDR', None)
    
    SecurityLog.objects.create(
        event_type=event_type,
        vehicle=vehicle,
        user=user,
        ip_address=ip,
        description=description,
        success=success
    )

def get_vehicle_by_vin(vin):
    """Get a vehicle by VIN or return None if not found"""
    try:
        return Vehicle.objects.get(vin=vin)
    except Vehicle.DoesNotExist:
        return None

def create_jwt_token(user_id, expiration_minutes=5):
    """Create a JWT token for secure authentication"""
    payload = {
        'user_id': user_id,
        'exp': datetime.utcnow() + timedelta(minutes=expiration_minutes),
        'iat': datetime.utcnow()
    }
    token = jwt.encode(payload, JWT_KEY, algorithm='RS256')
    return token

def verify_jwt_token(token):
    """Verify a JWT token and return the user_id if valid"""
    try:
        payload = jwt.decode(token, JWT_KEY, algorithms=['RS256'])
        return payload.get('user_id')
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

def calculate_cmac(frame_id, data):
    """Calculate CMAC for CAN frame"""
    h = hmac.new(CAN_KEY, digestmod=hashlib.sha256)
    h.update(frame_id.to_bytes(2, byteorder='big'))
    h.update(data)
    return h.digest()[:4]  # Return first 4 bytes

# Insecure API endpoints
@csrf_exempt
def insecure_auth(request):
    """Insecure authentication endpoint that returns a static session ID"""
    if request.method != 'POST':
        return JsonResponse({'error': 'Method not allowed'}, status=405)
    
    data = json.loads(request.body)
    username = data.get('userId', '')
    password = data.get('password', '')
    
    # No actual authentication, just log and return static SID
    log_security_event('AUTH', f'Insecure login attempt for {username}', success=True, request=request)
    
    return JsonResponse({
        'Sid': INSECURE_SID,
        'status': 'OK'
    })

@csrf_exempt
def insecure_vin_lookup(request):
    """Insecure VIN lookup that doesn't verify ownership"""
    if request.method != 'POST':
        return JsonResponse({'error': 'Method not allowed'}, status=405)
    
    # Check if Sid is in headers
    if 'HTTP_SID' not in request.META:
        return JsonResponse({'err': 'missing Sid'}, status=401)
    
    data = json.loads(request.body)
    vin = data.get('vin', '')
    
    # No validation of the Sid value!
    vehicle = get_vehicle_by_vin(vin)
    if not vehicle:
        log_security_event('API', f'VIN lookup failed for {vin}', success=False, request=request)
        return JsonResponse({'err': 'vin not found'}, status=404)
    
    log_security_event('API', f'Insecure VIN lookup for {vin}', vehicle=vehicle, success=True, request=request)
    
    return JsonResponse({
        'payload': {
            'profiles': [{
                'email': vehicle.owner_email,
                'phone': vehicle.phone,
                'loginId': vehicle.owner_email
            }]
        }
    })

@csrf_exempt
def insecure_demote_owner(request):
    """Insecure endpoint to demote the owner role without proper verification"""
    if request.method != 'POST':
        return JsonResponse({'error': 'Method not allowed'}, status=405)
    
    # Check if Sid is in headers
    if 'HTTP_SID' not in request.META:
        return JsonResponse({'err': 'missing Sid'}, status=401)
    
    data = json.loads(request.body)
    vin = data.get('vin', '')
    login_id = data.get('loginId', '')
    
    # No validation of the owner or permissions
    vehicle = get_vehicle_by_vin(vin)
    if not vehicle:
        log_security_event('API', f'Owner demotion failed for {vin}', success=False, request=request)
        return JsonResponse({'err': 'vin not found'}, status=404)
    
    vehicle.owner_role = 'SECONDARY'
    vehicle.save()
    
    log_security_event('API', f'Insecure owner demotion for {vin}, {login_id}', vehicle=vehicle, success=True, request=request)
    
    return JsonResponse({'status': 'demoted'})

@csrf_exempt
def insecure_add_owner(request):
    """Insecure endpoint to add a new owner without proper verification"""
    if request.method != 'POST':
        return JsonResponse({'error': 'Method not allowed'}, status=405)
    
    # Check if Sid is in headers
    if 'HTTP_SID' not in request.META:
        return JsonResponse({'err': 'missing Sid'}, status=401)
    
    data = json.loads(request.body)
    vin = data.get('vin', '')
    login_id = data.get('loginId', '')
    
    # No validation of permissions or original owner consent
    vehicle = get_vehicle_by_vin(vin)
    if not vehicle:
        # Create a new vehicle if it doesn't exist
        vehicle = Vehicle(
            vin=vin,
            owner_email=login_id,
            phone='000-000-0000',
            owner_role='PRIMARY'
        )
    else:
        # Update existing vehicle
        vehicle.owner_email = login_id
        vehicle.owner_role = 'PRIMARY'
    
    vehicle.save()
    
    log_security_event('API', f'Insecure owner added for {vin}, {login_id}', vehicle=vehicle, success=True, request=request)
    
    return JsonResponse({'status': 'attacker-now-owner'})

@csrf_exempt
def insecure_firmware_download(request):
    """Insecure firmware download without signature verification"""
    firmware_dir = Path(settings.BASE_DIR) / 'firmware'
    firmware_dir.mkdir(exist_ok=True)
    
    firmware_path = firmware_dir / 'latest.bin'
    
    # Create empty file if it doesn't exist
    if not firmware_path.exists():
        with open(firmware_path, 'wb') as f:
            f.write(b'DEMO FIRMWARE BINARY - NOT SIGNED')
    
    log_security_event('OTA', 'Insecure firmware download with no signature verification', success=True, request=request)
    
    return FileResponse(open(firmware_path, 'rb'))

@csrf_exempt
def insecure_can_send(request):
    """Insecure CAN frame transmission without authentication"""
    if request.method != 'POST':
        return JsonResponse({'error': 'Method not allowed'}, status=405)
    
    data = json.loads(request.body)
    frame_id = data.get('id', 0)
    frame_data = data.get('data', '')
    
    # No validation of the frame authenticity or authorization
    log_security_event('CAN', f'Insecure CAN frame sent: ID 0x{frame_id:X}, data: {frame_data}', success=True, request=request)
    
    return JsonResponse({'status': 'sent'})

# Secure API endpoints
@csrf_exempt
def secure_auth(request):
    """Secure authentication endpoint with proper JWT token"""
    if request.method != 'POST':
        return JsonResponse({'error': 'Method not allowed'}, status=405)
    
    data = json.loads(request.body)
    username = data.get('username', '')
    password = data.get('password', '')
    
    # Validate credentials (simplified for demo)
    if username == 'secure_user' and password == 'secure_password':
        token = create_jwt_token(username)
        log_security_event('AUTH', f'Secure login success for {username}', success=True, request=request)
        return JsonResponse({
            'access_token': token,
            'token_type': 'bearer'
        })
    else:
        log_security_event('AUTH', f'Secure login failed for {username}', success=False, request=request)
        return JsonResponse({'error': 'Invalid credentials'}, status=401)

@csrf_exempt
def secure_vin_lookup(request):
    """Secure VIN lookup with JWT verification"""
    if request.method != 'POST':
        return JsonResponse({'error': 'Method not allowed'}, status=405)
    
    # Extract and verify JWT token
    auth_header = request.META.get('HTTP_AUTHORIZATION', '')
    if not auth_header.startswith('Bearer '):
        log_security_event('API', 'Missing authentication token', success=False, request=request)
        return JsonResponse({'error': 'Missing authentication token'}, status=401)
    
    token = auth_header.split(' ')[1]
    user_id = verify_jwt_token(token)
    if not user_id:
        log_security_event('API', 'Invalid or expired token', success=False, request=request)
        return JsonResponse({'error': 'Invalid or expired token'}, status=401)
    
    data = json.loads(request.body)
    vin = data.get('vin', '')
    
    vehicle = get_vehicle_by_vin(vin)
    if not vehicle:
        log_security_event('API', f'VIN lookup failed for {vin}', success=False, request=request)
        return JsonResponse({'error': 'VIN not found'}, status=404)
    
    # Verify ownership (simplified for demo)
    if vehicle.owner_email != user_id and user_id != 'secure_user':
        log_security_event('API', f'Unauthorized VIN lookup for {vin}', vehicle=vehicle, success=False, request=request)
        return JsonResponse({'error': 'Unauthorized to access this vehicle'}, status=403)
    
    log_security_event('API', f'Secure VIN lookup for {vin}', vehicle=vehicle, success=True, request=request)
    
    return JsonResponse({
        'payload': {
            'profiles': [{
                'email': vehicle.owner_email,
                'phone': vehicle.phone,
                'loginId': vehicle.owner_email
            }]
        }
    })

@csrf_exempt
def secure_demote_owner(request):
    """Secure endpoint to demote owner with proper verification and MFA"""
    if request.method != 'POST':
        return JsonResponse({'error': 'Method not allowed'}, status=405)
    
    # Extract and verify JWT token
    auth_header = request.META.get('HTTP_AUTHORIZATION', '')
    if not auth_header.startswith('Bearer '):
        log_security_event('API', 'Missing authentication token', success=False, request=request)
        return JsonResponse({'error': 'Missing authentication token'}, status=401)
    
    token = auth_header.split(' ')[1]
    user_id = verify_jwt_token(token)
    if not user_id:
        log_security_event('API', 'Invalid or expired token', success=False, request=request)
        return JsonResponse({'error': 'Invalid or expired token'}, status=401)
    
    data = json.loads(request.body)
    vin = data.get('vin', '')
    login_id = data.get('loginId', '')
    mfa_code = data.get('mfa_code', '')
    
    # Verify MFA code (simplified for demo)
    if mfa_code != '000000':
        log_security_event('API', f'MFA verification failed for {user_id}', success=False, request=request)
        return JsonResponse({'error': 'Invalid MFA code'}, status=401)
    
    vehicle = get_vehicle_by_vin(vin)
    if not vehicle:
        log_security_event('API', f'Owner demotion failed for {vin}', success=False, request=request)
        return JsonResponse({'error': 'VIN not found'}, status=404)
    
    # Verify dealer code and permissions
    if vehicle.dealer_code != 'eDelivery':
        log_security_event('API', f'Unauthorized dealer code for {vin}', vehicle=vehicle, success=False, request=request)
        return JsonResponse({'error': 'Dealer not authorized'}, status=403)
    
    vehicle.owner_role = 'SECONDARY'
    vehicle.save()
    
    log_security_event('API', f'Secure owner demotion for {vin}, {login_id}', vehicle=vehicle, success=True, request=request)
    
    return JsonResponse({'status': 'demoted'})

@csrf_exempt
def secure_add_owner(request):
    """Secure endpoint to add new owner with proper verification and MFA"""
    if request.method != 'POST':
        return JsonResponse({'error': 'Method not allowed'}, status=405)
    
    # Extract and verify JWT token
    auth_header = request.META.get('HTTP_AUTHORIZATION', '')
    if not auth_header.startswith('Bearer '):
        log_security_event('API', 'Missing authentication token', success=False, request=request)
        return JsonResponse({'error': 'Missing authentication token'}, status=401)
    
    token = auth_header.split(' ')[1]
    user_id = verify_jwt_token(token)
    if not user_id:
        log_security_event('API', 'Invalid or expired token', success=False, request=request)
        return JsonResponse({'error': 'Invalid or expired token'}, status=401)
    
    data = json.loads(request.body)
    vin = data.get('vin', '')
    login_id = data.get('loginId', '')
    mfa_code = data.get('mfa_code', '')
    
    # Verify MFA code (simplified for demo)
    if mfa_code != '000000':
        log_security_event('API', f'MFA verification failed for {user_id}', success=False, request=request)
        return JsonResponse({'error': 'Invalid MFA code'}, status=401)
    
    vehicle = get_vehicle_by_vin(vin)
    if not vehicle:
        # Create a new vehicle
        vehicle = Vehicle(
            vin=vin,
            owner_email=login_id,
            phone='000-000-0000',
            owner_role='PRIMARY',
            dealer_code='eDelivery'
        )
    else:
        # Verify dealer code
        if vehicle.dealer_code != 'eDelivery':
            log_security_event('API', f'Unauthorized dealer code for {vin}', vehicle=vehicle, success=False, request=request)
            return JsonResponse({'error': 'Dealer not authorized'}, status=403)
        
        # Update existing vehicle
        vehicle.owner_email = login_id
        vehicle.owner_role = 'PRIMARY'
    
    vehicle.save()
    
    log_security_event('API', f'Secure owner added for {vin}, {login_id}', vehicle=vehicle, success=True, request=request)
    
    return JsonResponse({'status': 'new owner added (secure)'})

@csrf_exempt
def secure_firmware_download(request):
    """Secure firmware download with signature verification"""
    # Extract and verify JWT token
    auth_header = request.META.get('HTTP_AUTHORIZATION', '')
    if not auth_header.startswith('Bearer '):
        log_security_event('OTA', 'Missing authentication token for firmware download', success=False, request=request)
        return JsonResponse({'error': 'Missing authentication token'}, status=401)
    
    token = auth_header.split(' ')[1]
    user_id = verify_jwt_token(token)
    if not user_id:
        log_security_event('OTA', 'Invalid or expired token for firmware download', success=False, request=request)
        return JsonResponse({'error': 'Invalid or expired token'}, status=401)
    
    # Check for If-None-Match header for version verification
    etag = request.META.get('HTTP_IF_NONE_MATCH', '')
    
    # Get latest firmware version
    try:
        latest_firmware = FirmwareVersion.objects.filter(is_signed=True).latest('created_at')
        # Verify firmware version and prevent rollback
        if etag and etag == latest_firmware.hash:
            log_security_event('OTA', 'Firmware already up to date', success=True, request=request)
            return JsonResponse({'status': 'Already up to date'}, status=304)
        
        firmware_path = Path(latest_firmware.file_path)
        if not firmware_path.exists():
            log_security_event('OTA', 'Firmware file not found', success=False, request=request)
            return JsonResponse({'error': 'Firmware file not found'}, status=404)
        
        log_security_event('OTA', f'Secure firmware download: v{latest_firmware.version}', success=True, request=request)
        
        response = FileResponse(open(firmware_path, 'rb'))
        response['ETag'] = latest_firmware.hash
        return response
    except FirmwareVersion.DoesNotExist:
        log_security_event('OTA', 'No signed firmware available', success=False, request=request)
        return JsonResponse({'error': 'No signed firmware available'}, status=404)

@csrf_exempt
def secure_can_send(request):
    """Secure CAN frame transmission with CMAC verification"""
    if request.method != 'POST':
        return JsonResponse({'error': 'Method not allowed'}, status=405)
    
    # Extract and verify JWT token
    auth_header = request.META.get('HTTP_AUTHORIZATION', '')
    if not auth_header.startswith('Bearer '):
        log_security_event('CAN', 'Missing authentication token for CAN access', success=False, request=request)
        return JsonResponse({'error': 'Missing authentication token'}, status=401)
    
    token = auth_header.split(' ')[1]
    user_id = verify_jwt_token(token)
    if not user_id:
        log_security_event('CAN', 'Invalid or expired token for CAN access', success=False, request=request)
        return JsonResponse({'error': 'Invalid or expired token'}, status=401)
    
    data = json.loads(request.body)
    frame_id = data.get('id', 0)
    frame_data = bytes.fromhex(data.get('data', ''))
    cmac = bytes.fromhex(data.get('cmac', ''))
    
    # Verify CMAC
    expected_cmac = calculate_cmac(frame_id, frame_data)
    if not hmac.compare_digest(cmac, expected_cmac):
        log_security_event('CAN', f'Invalid CMAC for CAN frame: ID 0x{frame_id:X}', success=False, request=request)
        return JsonResponse({'error': 'Invalid CMAC', 'status': 'blocked'}, status=403)
    
    log_security_event('CAN', f'Secure CAN frame sent: ID 0x{frame_id:X}', success=True, request=request)
    
    return JsonResponse({'status': 'sent'})

# Simulation endpoints
@api_view(['GET'])
def get_security_logs(request):
    """Get security logs for simulation display"""
    logs = SecurityLog.objects.all().order_by('-timestamp')[:50]
    
    logs_data = []
    for log in logs:
        logs_data.append({
            'id': log.id,
            'timestamp': log.timestamp.isoformat(),
            'event_type': log.event_type,
            'vehicle': log.vehicle.vin if log.vehicle else None,
            'user': log.user.username if log.user else None,
            'ip_address': log.ip_address,
            'description': log.description,
            'success': log.success
        })
    
    return Response(logs_data)

@api_view(['POST'])
def simulate_attack(request):
    """Simulate an attack sequence for the demonstration"""
    mode = request.data.get('mode', 'insecure')
    attack_type = request.data.get('attack_type', 'ownership')
    
    if mode == 'secure':
        # Simulate attack being blocked in secure mode
        log_security_event('ATTACK', f'Attack attempt ({attack_type}) blocked by security measures', success=False, request=request)
        time.sleep(1)  # Simulate processing time
        
        # Generate which security feature blocked the attack
        security_features = {
            'ownership': 'OAuth + MFA Security',
            'firmware': 'TUF Firmware Security',
            'can': 'CAN-FD + CMAC Guardian'
        }
        blocking_feature = security_features.get(attack_type, 'Security System')
        
        return Response({
            'status': 'blocked',
            'blocking_feature': blocking_feature,
            'message': f'Attack was blocked by {blocking_feature}'
        })
    else:
        # Simulate successful attack in insecure mode
        steps = []
        
        if attack_type == 'ownership':
            # Step 1: Authentication bypass
            log_security_event('ATTACK', 'Step 1: Authentication bypass - Accessing dealer portal', success=True, request=request)
            steps.append('Authentication bypass successful')
            time.sleep(0.5)
            
            # Step 2: Leak owner information
            log_security_event('ATTACK', 'Step 2: Owner information leaked', success=True, request=request)
            steps.append('Owner information leaked')
            time.sleep(0.5)
            
            # Step 3: Demote original owner
            log_security_event('ATTACK', 'Step 3: Original owner permissions demoted', success=True, request=request)
            steps.append('Original owner demoted')
            time.sleep(0.5)
            
            # Step 4: Add attacker as primary owner
            log_security_event('ATTACK', 'Step 4: Attacker promoted to primary owner', success=True, request=request)
            steps.append('Attacker gained primary ownership')
            time.sleep(0.5)
            
        elif attack_type == 'firmware':
            # Step 1: Authentication bypass
            log_security_event('ATTACK', 'Step 1: Authentication bypass - Accessing OTA system', success=True, request=request)
            steps.append('OTA system access gained')
            time.sleep(0.5)
            
            # Step 2: Upload malicious firmware
            log_security_event('ATTACK', 'Step 2: Malicious firmware uploaded', success=True, request=request)
            steps.append('Malicious firmware uploaded')
            time.sleep(0.5)
            
            # Step 3: Force rollback to vulnerable version
            log_security_event('ATTACK', 'Step 3: Forced rollback to vulnerable version', success=True, request=request)
            steps.append('Rollback to vulnerable version forced')
            time.sleep(0.5)
            
            # Step 4: Execute malicious code
            log_security_event('ATTACK', 'Step 4: Malicious code executed on vehicle', success=True, request=request)
            steps.append('Malicious code executed')
            time.sleep(0.5)
            
        elif attack_type == 'can':
            # Step 1: Sniff CAN traffic
            log_security_event('ATTACK', 'Step 1: CAN bus traffic sniffed', success=True, request=request)
            steps.append('CAN bus traffic analysis complete')
            time.sleep(0.5)
            
            # Step 2: Identify unlock command
            log_security_event('ATTACK', 'Step 2: Unlock command ID identified', success=True, request=request)
            steps.append('Unlock command ID found')
            time.sleep(0.5)
            
            # Step 3: Forge unauthorized CAN frame
            log_security_event('ATTACK', 'Step 3: Unauthorized CAN frame crafted', success=True, request=request)
            steps.append('Unauthorized CAN frame crafted')
            time.sleep(0.5)
            
            # Step 4: Send command to vehicle
            log_security_event('ATTACK', 'Step 4: Unauthorized command sent to vehicle', success=True, request=request)
            steps.append('Vehicle compromised')
            time.sleep(0.5)
        
        return Response({
            'status': 'successful',
            'steps': steps,
            'message': 'Attack simulation completed successfully'
        })

@api_view(['POST'])
def reset_simulation(request):
    """Reset the simulation state"""
    # Clear all logs except the first 10 (to preserve some history)
    logs_to_keep = SecurityLog.objects.all().order_by('-timestamp')[:10]
    logs_to_keep_ids = [log.id for log in logs_to_keep]
    SecurityLog.objects.exclude(id__in=logs_to_keep_ids).delete()
    
    return Response({'status': 'reset', 'message': 'Simulation has been reset'})