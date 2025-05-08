from channels.generic.websocket import WebsocketConsumer
from django.shortcuts import get_object_or_404
from .models import Group, GroupMessage
from django.template.loader import render_to_string
import json

class ChatConsumer(WebsocketConsumer):
    def connect(self):
        self.user = self.scope['user']
        self.group_name = self.scope['url_route']['kwargs']['chat_room_name']
        self.chat_room = get_object_or_404(Group, name=self.group_name)
        self.accept()
    
    def receive(self, text_data):
        
        test_json_data = json.loads(text_data)
        message = test_json_data.get('message', '').strip()
        if not message:
            print("No message received")
            return
        print(message)
        try:
            group_message = GroupMessage.objects.create(
                group=self.chat_room,
                user=self.user,
                message=message
            )
            group_message.save()
        except Exception as e:
            print(f"Error saving message: {e}")
            return
        context ={
            'message': group_message,
            'user': self.user,
        }
        html = render_to_string('chat/partials/chat_message_p.html', context=context)
        
        self.send(text_data=html)