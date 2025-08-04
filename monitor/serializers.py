from rest_framework import serializers
from .models import Domain, RecordLog


class DomainSerializer(serializers.ModelSerializer):
    """Serializer for Domain model"""
    
    last_known_ips_list = serializers.SerializerMethodField()
    latest_check = serializers.SerializerMethodField()
    
    class Meta:
        model = Domain
        fields = [
            'id', 'name', 'is_active', 'last_known_ips', 'last_known_ips_list',
            'updated_at', 'created_at', 'latest_check'
        ]
        read_only_fields = ['id', 'last_known_ips', 'updated_at', 'created_at']
    
    def get_last_known_ips_list(self, obj):
        """Return last known IPs as a list"""
        return obj.get_last_known_ips_list()
    
    def get_latest_check(self, obj):
        """Return the latest record log for this domain"""
        latest_log = obj.record_logs.first()
        if latest_log:
            return RecordLogSerializer(latest_log).data
        return None


class DomainCreateSerializer(serializers.ModelSerializer):
    """Serializer for creating new domains"""
    
    class Meta:
        model = Domain
        fields = ['name', 'is_active']
    
    def validate_name(self, value):
        """Validate domain name format"""
        import re
        
        # Basic domain name validation
        domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
        
        if not re.match(domain_pattern, value):
            raise serializers.ValidationError("Invalid domain name format.")
        
        # Check if domain already exists
        if Domain.objects.filter(name=value).exists():
            raise serializers.ValidationError("Domain already exists.")
            
        return value.lower().strip()


class RecordLogSerializer(serializers.ModelSerializer):
    """Serializer for RecordLog model"""
    
    ips_list = serializers.SerializerMethodField()
    domain_name = serializers.CharField(source='domain.name', read_only=True)
    
    class Meta:
        model = RecordLog
        fields = [
            'id', 'domain_name', 'ips', 'ips_list', 'is_change', 
            'timestamp', 'error_message'
        ]
        read_only_fields = ['id', 'timestamp']
    
    def get_ips_list(self, obj):
        """Return IPs as a list"""
        return obj.get_ips_list()


class DomainDetailSerializer(serializers.ModelSerializer):
    """Detailed serializer for Domain with recent logs"""
    
    last_known_ips_list = serializers.SerializerMethodField()
    recent_logs = serializers.SerializerMethodField()
    total_logs = serializers.SerializerMethodField()
    changes_count = serializers.SerializerMethodField()
    
    class Meta:
        model = Domain
        fields = [
            'id', 'name', 'is_active', 'last_known_ips', 'last_known_ips_list',
            'updated_at', 'created_at', 'recent_logs', 'total_logs', 'changes_count'
        ]
        read_only_fields = ['id', 'last_known_ips', 'updated_at', 'created_at']
    
    def get_last_known_ips_list(self, obj):
        """Return last known IPs as a list"""
        return obj.get_last_known_ips_list()
    
    def get_recent_logs(self, obj):
        """Return the 10 most recent record logs"""
        recent_logs = obj.record_logs.all()[:10]
        return RecordLogSerializer(recent_logs, many=True).data
    
    def get_total_logs(self, obj):
        """Return total number of logs for this domain"""
        return obj.record_logs.count()
    
    def get_changes_count(self, obj):
        """Return number of times this domain's IP changed"""
        return obj.record_logs.filter(is_change=True).count()
