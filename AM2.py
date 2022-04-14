from socket import *
import pickle
import json
from datetime import datetime


def get_subject(request):
    """
        Obtém os atributos referentes ao "subject" da requisição.
        Input: requisição
        Output: atributos de "subject" em json.
    """
    request = json.loads(request)

    sub_attr = {
        "id": request.get("subject").get("attributes").get("name"),
        "attributes": request.get("subject").get("attributes")
    }

    return sub_attr


def get_resource(request):
    """
            Obtém os atributos referentes ao "resource" da requisição.
            Input: requisição
            Output: atributos de "resource" em formato json.
        """

    request = json.loads(request)

    res_attr = {
        "id": request.get("resource").get("attributes").get("source"),
        "attributes": request.get("resource").get("attributes")
    }

    return res_attr


def get_request_context(request, address, port):
    """
        Obtém o contexto da solicitação.
        Input: requisição, socket de conexão do lado do emissor, endereço de porta.
        Output: contexto da requisição em formato json.
    """

    date_time = datetime.now()

    req_context = {
        "ip": address[0],
        "port": address[1],
        "time": date_time.strftime('%H:%M'),
        "date": date_time.strftime('%d/%m/%Y'),
        "connection": str(port),
        "device": 'qualquer um',
        "protocol": '1883'
    }

    return req_context


def access_composer(subject, resource, context):
    """
        Forma um objeto json a ser enviado para o PDA que será base para o Access Request.
        Input: objetos json com atributos.
        Output: objeto json no formato Access Request.
    """

    access_request = {
        "subject": subject,
        "resource": resource,
        "context": context,
        "action": {
            "id": 'get',
            "attributes": {'method': 'get'}
        }
    }

    return access_request


def send_access(data):
    """
        Envia a mensagem com os atributos para o PDA.
        Input: json no formato Access Request.
        Ouput: resposta PDA.
    """

    host = 'localhost'
    port = 50000
    sock = socket(AF_INET, SOCK_STREAM)
    sock.connect((host, port))
    print('Conexão com PDA estabelecida!')

    access_request = pickle.dumps(data)
    sock.send(access_request)
    response = sock.recv(1024)
    sock.close()

    return pickle.loads(response)
    #return pickle.loads(response)


def receive_context():
    """
        Recebe os dados criptografados enviados do EA.
        Input: none
        Output: contexto criptografado.
    """

    host = 'localhost'
    port = 50004

    sock = socket(AF_INET, SOCK_STREAM)
    sock.bind((host, port))
    sock.listen(1)
    print('Waiting for context...')
    connection, address = sock.accept()
    context = connection.recv(1024)
    context = pickle.loads(context)
    sock.close()

    return context


def request_context(connection, request, evaluation):
    """
        Realiza solicitação de contexto para o CM.
        Input: socket, especificação de contexto requerido e resultado da avaliação do PDA.
        Output: contexto criptografado enviado pelo EA.
    """

    host = 'localhost'
    port = 50006

    source = request.get('resource').get('attributes').get('source')
    destination = connection
    context = []

    for data in request.get('resource').get('attributes').get('name'):
        context.append(data)

    print("Evaluation = {}".format(evaluation))
    context_request = {
        'source': source,
        'context': context,
        'destination': destination,
        'crypto': evaluation
    }

    try:
        sock = socket(AF_INET, SOCK_STREAM)
        sock.connect((host, port))
        print ('Conexão com CM estabelecida!')

        sock.send(pickle.dumps(context_request))
        sock.close()

    except ConnectionRefusedError:
        return print('Conexão com CM não foi estabelecida!')

    response_context = receive_context()

    return response_context


def main():
    host = 'localhost'
    port = 50003
    log = []

    while True:
        sock = socket(SOCK_DGRAM, AF_INET)
        sock.bind((host, port))
        print('AM is running! Waiting for requests...')
        data, address = sock.recvfrom(1024)
        print('Connection received from: IP {}, PORT {}.'.format(address[0],address[1]))

        request = pickle.loads(data)

        subject = get_subject(request)
        context = get_request_context(request, address, port)
        resource = get_resource(request)

        access_request = access_composer(subject, resource, context)

        evaluation = send_access(access_request)

        if evaluation == 'Deny':
            msg = 'Access Denied.'
            sock.sendto(msg.encode(), address)
            sock.close()

        else:
            print('Requisitando context...')
            context = request_context(address, access_request, evaluation)
            sock.sendto(context, address)
            sock.close()


if __name__ == '__main__':
    main()
