# Generated by Django 5.2 on 2025-05-09 12:20

from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('app', '0003_alter_groupmessage_message'),
    ]

    operations = [
        migrations.AddField(
            model_name='group',
            name='online_users',
            field=models.ManyToManyField(blank=True, related_name='online_count', to=settings.AUTH_USER_MODEL),
        ),
    ]
