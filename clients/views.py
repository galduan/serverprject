# Create your views here.
import json

from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt

# Create your views here.
from .models import Client


# Create your views here.

@csrf_exempt
def client_create_view(request):
    if request.method == 'POST':
        body_unicode = request.body.decode('utf-8')
        data = json.loads(body_unicode) or None
        clientFirstName = data['fname']
        clientLastName = data['lname']
        saveclient = Client(firstName=clientFirstName, lastName=clientLastName)
        saveclient.save()

        # retrieve last inserted client
        last_client = Client.objects.latest('id')
        # send the response to the frontend
        return JsonResponse(
            {'id': last_client.id, 'firstName': last_client.firstName, 'lastName': last_client.lastName})
    else:
        data = request.GET
        clientFirstName = data['fname']
        clientLastName = data['lname']
        saveclient = Client(firstName=clientFirstName, lastName=clientLastName)
        saveclient.save()

        get_client_query = f"SELECT * FROM clients_client ORDER BY id DESC LIMIT 1;"
        last_client = Client.objects.raw(get_client_query)
        return JsonResponse(
            {'id': last_client[0].id, 'firstName': last_client[0].firstName, 'lastName': last_client[0].lastName})
