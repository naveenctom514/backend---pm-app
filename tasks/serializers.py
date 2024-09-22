from rest_framework import serializers
from django.contrib.auth.models import User 

from .models import Admin, Customer, Member, Team , Task


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = "__all__"


class AdminDepthOneSerializer(serializers.ModelSerializer):
    class Meta:
        model = Admin
        fields ="__all__"
        depth = 1


class CustomerSerializer(serializers.ModelSerializer):
    class Meta:
        model = Customer
        fields = "__all__"


class MemberSerializer(serializers.ModelSerializer):
    class Meta:
        model = Member
        fields = "__all__"


class TesmSerializer(serializers.ModelSerializer):
    class Meta:
        model = Team
        fields = "__all__"
        depth=1


class TaskSerializer(serializers.ModelSerializer):
    class Meta:
        model = Task
        fields = "__all__"
        depth=2
