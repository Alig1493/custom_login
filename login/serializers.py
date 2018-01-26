from django.contrib.auth import get_user_model
from django.utils.translation import ugettext_lazy as _
from django.shortcuts import get_object_or_404

from rest_framework import serializers
from rest_framework.serializers import ValidationError

User = get_user_model()


class RegisterSerializer(serializers.ModelSerializer):

    password1 = serializers.CharField(style={'input_type': 'password'}, write_only=True)
    password2 = serializers.CharField(style={'input_type': 'password'}, write_only=True)

    class Meta:
        model = User
        fields = ('email', 'password1', 'password2',)

    def validate(self, attrs):

        password2 = attrs.pop('password2', '')

        if attrs['password1'] != password2:
            msg = _('Passwords do not match.')
            raise ValidationError(msg)

        return attrs

    def create(self, validated_data):
        password = validated_data.pop('password1', None)
        user = User.objects.create(**validated_data)
        user.set_password(password)
        user.save()
        return user


class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField(required=False)
    password = serializers.CharField(write_only=True, style={'input_type': 'password'})

    def _validate_email(self, email, password):
        # Should return 404 if no user found with this email
        # This is intentional as per requirements and specification
        user = get_object_or_404(User, email__iexact=email)
        if user and user.check_password(password):
            return user

    def validate(self, attrs):
        email = attrs.get('email')
        password = attrs.get('password')

        if email and password:
            user = self._validate_email(email, password)
        else:
            msg = _('Must include "email" and "password".')
            raise ValidationError(msg)

        if not user:
            msg = _('Unable to log in with provided credentials.')
            raise ValidationError(msg)

        if not user.is_active:
            msg = _('User account is disabled.')
            raise ValidationError(msg)

        # Everything passed. That means password is accepted. So return the user
        attrs['user'] = user
        return attrs


class UserDetailsSerializer(serializers.ModelSerializer):

    class Meta:
        model = User
        fields = ('id', 'first_name', 'last_name', 'email', 'is_superuser',)
        read_only_fields = ('is_superuser',)


class UserPublicSerializer(serializers.ModelSerializer):

    full_name = serializers.CharField(source='get_full_name')

    class Meta:
        model = User
        fields = ('id', 'full_name', 'email')

