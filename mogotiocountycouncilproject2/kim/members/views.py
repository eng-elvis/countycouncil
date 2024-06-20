import requests
from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from .forms import SignupForm, LoginForm
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.template.loader import render_to_string
from django.http import HttpResponse, JsonResponse
import pdfkit
import os
from django.conf import settings
from django.utils.timezone import now
import qrcode
import io
import base64
import json
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.forms import PasswordResetForm, SetPasswordForm
from django.contrib.auth.tokens import default_token_generator
from django.contrib.auth import views as auth_views
from django.contrib.auth.models import User
from django.contrib.auth import get_user_model
from django.utils.http import urlsafe_base64_decode
from django.http import Http404


# M-Pesa credentials
MPESA_CONSUMER_KEY = ''
MPESA_CONSUMER_SECRET = ''
MPESA_SHORTCODE = ''
MPESA_PASSKEY = ''

# Function to get M-Pesa OAuth token
def get_mpesa_token():
    auth_url = 'https://sandbox.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials'
    response = requests.get(auth_url, auth=(MPESA_CONSUMER_KEY, MPESA_CONSUMER_SECRET))
    return response.json().get('access_token')

# Function to initiate STK Push
def stk_push(number, amount, description):
    token = get_mpesa_token()
    headers = {'Authorization': f'Bearer {token}'}
    stk_url = 'https://sandbox.safaricom.co.ke/mpesa/stkpush/v1/processrequest'
    timestamp = now().strftime('%Y%m%d%H%M%S')
    password = base64.b64encode((MPESA_SHORTCODE + MPESA_PASSKEY + timestamp).encode()).decode('utf-8')
    
    payload = {
        "BusinessShortCode": ,
        "Password": "",
        "Timestamp": "20240610170727",
        "TransactionType": "CustomerPayBillOnline",
        "Amount": amount,
        "PartyA": ,
        "PartyB": ,
        "PhoneNumber": number,
        "CallBackURL": "https://yourdomain.com/payment/callback",
        "AccountReference": "",
        "TransactionDesc": description
    }

    response = requests.post(stk_url, json=payload, headers=headers)
    return response.json()

@login_required(login_url='login')
def home(request):
    return render(request, 'home.html')

@login_required(login_url='login')
def payment(request):
    if request.method == 'GET':
        payment_type = request.GET.get('payment_type')
        if payment_type == 'vendor':
            amount = 1
        elif payment_type == 'cess':
            amount = 50
        elif payment_type == 'rental_tax':
            amount = 1200
        elif payment_type == 'business_permit':
            amount = 1000
        elif payment_type == 'Land_tax':
            amount = 2000   
        else:
            amount = 0
        return render(request, 'payment.html', {'payment_type': payment_type, 'amount': amount})
    return redirect('home')

def generate_invoice(number, amount, description, mpesa_details):
    current_time = now()

    # Generate QR code
    qr_data = f"Invoice Number: {number}\nAmount: {amount}\nDescription: {description}"
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(qr_data)
    qr.make(fit=True)
    img = qr.make_image(fill='black', back_color='white')

    # Save QR code as base64
    buffer = io.BytesIO()
    img.save(buffer, format="PNG")
    qr_code_base64 = base64.b64encode(buffer.getvalue()).decode('utf-8')

    invoice_html = render_to_string('invoice.html', {
        'number': number,
        'amount': amount,
        'description': description,
        'current_time': current_time,
        'qr_code_base64': qr_code_base64,
        'mpesa_details': mpesa_details  # Pass M-Pesa details to template
    })
    pdf_file_name = f'invoice_{number}.pdf'
    pdf_file_path = os.path.join(settings.MEDIA_ROOT, pdf_file_name)
    pdfkit.from_string(invoice_html, pdf_file_path)
    return os.path.join(settings.MEDIA_URL, pdf_file_name)

@login_required(login_url='login')
def payment_process_view(request):
    if request.method == 'POST':
        number = request.POST.get('number')
        payment_type = request.POST.get('payment_type')
        if payment_type == 'vendor':
            amount = 1
            description = 'Vendor Payment'
        elif payment_type == 'cess':
            amount = 50
            description = 'Cess Collection'
        elif payment_type == 'rental_tax':
            amount = 1200
            description = 'Rental Tax'
        elif payment_type == 'business_permit':
            amount = 1000
            description = 'Business Permit'
        elif payment_type == 'Land_tax':
            amount = 2000
            description = 'Land tax'
        else:
            amount = 0
            description = 'Unknown Payment Type'

        stk_response = stk_push(number, amount, description)
        if stk_response.get('ResponseCode') == '0':
            checkout_request_id = stk_response.get('CheckoutRequestID')
            return render(request, 'payment_status.html', {
                'checkout_request_id': checkout_request_id,
                'number': number,
                'amount': amount,
                'description': description,
                'mpesa_details': stk_response
            })
        else:
            messages.error(request, 'Payment initiation failed. Please try again.')
            return render(request, 'home.html')


def user_register(request):
    if request.method == 'POST':
        form = SignupForm(request.POST)
        if form.is_valid():
            form.save()
            user = form.cleaned_data.get('username')
            messages.success(request, 'Account was created for ' + user)
            return redirect('login')
    else:
        form = SignupForm()
    return render(request, 'register.html', {'form': form})

def user_login(request):
    if request.method == 'POST':
        form = LoginForm(request.POST)
        if form.is_valid():
            username = form.cleaned_data['username']
            password = form.cleaned_data['password']
            user = authenticate(request, username=username, password=password)
            if user is not None:
                login(request, user)
                return redirect('home')
            else:
                messages.info(request, 'Phone number or password is incorrect')
    else:
        form = LoginForm()
    return render(request, 'login.html', {'form': form})

@login_required(login_url='login')
def user_logout(request):
    logout(request)
    return redirect('login')

@csrf_exempt
def payment_callback(request):
    if request.method == 'POST':
        data = json.loads(request.body)
        # Process the payment callback data here
        checkout_request_id = data['Body']['stkCallback']['CheckoutRequestID']
        result_code = data['Body']['stkCallback']['ResultCode']
        
        # Store the payment result in a session or database for later checking
        request.session['payment_status'] = {
            'checkout_request_id': checkout_request_id,
            'result_code': result_code
        }

        return JsonResponse({'status': 'ok'})
    return JsonResponse({'status': 'invalid request'}, status=400)

@login_required(login_url='login')
def payment_status_view(request):
    checkout_request_id = request.GET.get('checkout_request_id')

    if not checkout_request_id:
        return JsonResponse({'status': 'error', 'message': 'Invalid request ID'})

    # Assume you have a method to check payment status
    status_response = check_payment_status(checkout_request_id)
    
    if status_response == 'success':
        return JsonResponse({'status': 'success'})
    elif status_response == 'error':
        return JsonResponse({'status': 'payment_error'})
    else:
        return JsonResponse({'status': 'pending'})

@login_required(login_url='login')
def payment_success_view(request):
    number = request.GET.get('number')
    amount = request.GET.get('amount')
    description = request.GET.get('description')
    mpesa_details = request.GET.get('mpesa_details')

    invoice_path = generate_invoice(number, amount, description, mpesa_details)
    
    return render(request, 'success.html', {'invoice_path': invoice_path})


def check_payment_status(checkout_request_id):
    token = get_mpesa_token()
    headers = {'Authorization': f'Bearer {token}'}
    status_url = 'https://sandbox.safaricom.co.ke/mpesa/stkpushquery/v1/query'
    
    payload = {
        'BusinessShortCode': MPESA_SHORTCODE,
        'Password': base64.b64encode((MPESA_SHORTCODE + MPESA_PASSKEY + now().strftime('%Y%m%d%H%M%S')).encode()).decode('utf-8'),
        'Timestamp': now().strftime('%Y%m%d%H%M%S'),
        'CheckoutRequestID': checkout_request_id,
    }

    response = requests.post(status_url, json=payload, headers=headers)
    result = response.json()
    
    # Check the result for status
    if result.get('ResultCode') == '0':
        return 'success'
    elif result.get('ResultCode') == '1032':  # Example error code for wrong PIN
        return 'payment_error'
    else:
        return 'pending'


def generate_invoice(number, amount, description, mpesa_details):
    current_time = now()

    # Generate QR code
    qr_data = f"Invoice Number: {number}\nAmount: {amount}\nDescription: {description}"
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(qr_data)
    qr.make(fit=True)
    img = qr.make_image(fill='black', back_color='white')

    # Save QR code as base64
    buffer = io.BytesIO()
    img.save(buffer, format="PNG")
    qr_code_base64 = base64.b64encode(buffer.getvalue()).decode('utf-8')

    invoice_html = render_to_string('invoice.html', {
        'number': number,
        'amount': amount,
        'description': description,
        'current_time': current_time,
        'qr_code_base64': qr_code_base64,
        'mpesa_details': mpesa_details  # Pass M-Pesa details to template
    })
    pdf_file_name = f'invoice_{number}.pdf'
    pdf_file_path = os.path.join(settings.MEDIA_ROOT, pdf_file_name)
    pdfkit.from_string(invoice_html, pdf_file_path)
    return os.path.join(settings.MEDIA_URL, pdf_file_name)
    
  
def password_reset(request):
    if request.method == 'POST':
        form = PasswordResetForm(request.POST)
        if form.is_valid():
            form.save(request=request)
            return render(request, 'password_reset_done.html')
    else:
        form = PasswordResetForm()
    return render(request, 'password_reset_form.html', {'form': form})

User = get_user_model()

def password_reset_confirm(request, uidb64, token):
    try:
        uid = urlsafe_base64_decode(uidb64).decode()
        user = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None

    if user is not None and default_token_generator.check_token(user, token):
        if request.method == 'POST':
            form = SetPasswordForm(user, request.POST)
            if form.is_valid():
                form.save()
                return redirect('password_reset_complete')
        else:
            form = SetPasswordForm(user)
        return render(request, 'password_reset_confirm.html', {'form': form})
    else:
        raise Http404("Invalid password reset link")
        
def payment_error_view(request):
    return render(request, 'payment_error.html')
