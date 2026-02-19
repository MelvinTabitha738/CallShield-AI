# backend_apps/analytics/serializers.py

from rest_framework import serializers


class UserStatsSerializer(serializers.Serializer):
    """Serializer for user analytics stats."""
    
    protection = serializers.DictField()
    calls_summary = serializers.DictField()
    community = serializers.DictField()
    recent_activity = serializers.ListField()
    scam_types_encountered = serializers.ListField()
    most_common_scam = serializers.CharField(allow_null=True)


class SystemOverviewSerializer(serializers.Serializer):
    """Serializer for admin system overview."""
    
    users = serializers.DictField()
    detection = serializers.DictField()
    database = serializers.DictField()
    ml_model = serializers.DictField()


class TimeBasedActivitySerializer(serializers.Serializer):
    """Serializer for time-based activity stats."""
    
    today = serializers.DictField()
    week = serializers.DictField()
    month = serializers.DictField()


class ScamTrendsSerializer(serializers.Serializer):
    """Serializer for scam trends."""
    
    distribution = serializers.ListField()
    trending_up = serializers.ListField()
    trending_down = serializers.ListField()


class UserEngagementSerializer(serializers.Serializer):
    """Serializer for user engagement metrics."""
    
    dau = serializers.IntegerField()
    wau = serializers.IntegerField()
    mau = serializers.IntegerField()
    avg_sessions_per_user = serializers.FloatField()
    avg_reports_per_user = serializers.FloatField()
    training_contributor_percentage = serializers.FloatField()
    top_contributors = serializers.ListField()


class CommunityImpactSerializer(serializers.Serializer):
    """Serializer for public community impact stats."""
    
    total_scams_blocked = serializers.IntegerField()
    total_users_protected = serializers.IntegerField()
    success_rate = serializers.FloatField()
    active_now = serializers.IntegerField()
    calls_today = serializers.IntegerField()
    scams_today = serializers.IntegerField()
    total_reports = serializers.IntegerField()
    active_contributors = serializers.IntegerField()
    training_contributions = serializers.IntegerField()


class ScamIntelligenceSerializer(serializers.Serializer):
    """Serializer for public scam intelligence."""
    
    distribution = serializers.ListField()
    most_common = serializers.CharField(allow_null=True)