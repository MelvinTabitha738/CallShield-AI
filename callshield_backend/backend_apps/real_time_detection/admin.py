from django.contrib import admin
from django.utils.html import format_html
from .models import (
    CallSession,
    TranscriptChunk,
    RiskAlert,
    ConfirmedScamConversation,
)


@admin.register(CallSession)
class CallSessionAdmin(admin.ModelAdmin):

    list_display = (
        'get_short_id',
        'user',
        'status',
        'initial_risk_score',
        'peak_risk_score',
        'get_risk_badge',
        'alert_triggered',
        'auto_report_recommended',
        'chunks_processed',
        'get_duration',
        'content_deleted',
        'started_at',
    )
    list_filter = (
        'status',
        'alert_triggered',
        'user_confirmed_scam',
        'content_deleted',
        'detected_scam_type',
    )
    search_fields = ('id', 'caller_number_hash', 'user__phone_number')
    readonly_fields = (
        'id', 'started_at', 'last_updated',
        'content_deleted_at', 'caller_number_hash',
    )
    ordering = ('-started_at',)

    fieldsets = (
        ('Session', {
            'fields': ('id', 'user', 'status', 'device_id', 'app_version'),
        }),
        ('Caller (Hash Only)', {
            'fields': ('caller_number_hash',),
            'description': '🔒 Phone number is never stored as plaintext.',
        }),
        ('Risk Tracking', {
            'fields': (
                'initial_risk_score', 'current_risk_score',
                'peak_risk_score', 'final_risk_score',
                'ml_confidence', 'alert_threshold',
                'alert_triggered', 'alert_count',
                'auto_report_recommended',  
            ),
        }),
        ('Detection Results', {
            'fields': ('detected_scam_type', 'detected_patterns'),
        }),
        ('User Feedback', {
            'fields': ('user_confirmed_scam', 'user_feedback_notes'),
        }),
        ('Privacy & Deletion', {
            'fields': (
                'content_deleted', 'content_deleted_at', 'deletion_reason',
            ),
        }),
        ('Timestamps', {
            'fields': (
                'started_at', 'ended_at',
                'call_duration_seconds', 'chunks_processed', 'last_updated',
            ),
        }),
    )

    def get_short_id(self, obj):
        return str(obj.id)[:8] + '…'
    get_short_id.short_description = 'Session ID'

    def get_duration(self, obj):
        return obj.get_duration_display()
    get_duration.short_description = 'Duration'

    def get_risk_badge(self, obj):
        score = obj.peak_risk_score
        if score >= 70:
            color, label = '#e74c3c', 'HIGH'
        elif score >= 40:
            color, label = '#f39c12', 'MEDIUM'
        elif score >= 20:
            color, label = '#3498db', 'LOW'
        else:
            color, label = '#27ae60', 'SAFE'
        return format_html(
            '<span style="background:{};color:#fff;padding:2px 10px;'
            'border-radius:4px;font-size:11px;">{}</span>',
            color, label,
        )
    get_risk_badge.short_description = 'Peak Risk'


@admin.register(TranscriptChunk)
class TranscriptChunkAdmin(admin.ModelAdmin):

    list_display = (
        'session',
        'chunk_number',
        'speaker',
        'chunk_risk_score',
        'ml_analyzed',
        'ml_confidence',
        'received_at',
    )
    list_filter  = ('speaker', 'ml_analyzed')
    search_fields = ('session__id',)
    readonly_fields = ('id', 'received_at')
    ordering = ('session', 'chunk_number')


@admin.register(RiskAlert)
class RiskAlertAdmin(admin.ModelAdmin):

    list_display = (
        'session',
        'alert_type',
        'risk_score_at_alert',
        'confidence_at_alert',
        'detected_scam_type',
        'user_dismissed',
        'user_ended_call',
        'triggered_at',
    )
    list_filter = (
        'alert_type',
        'user_dismissed',
        'user_ended_call',
        'detected_scam_type',
    )
    readonly_fields = ('id', 'triggered_at')
    ordering = ('-triggered_at',)


@admin.register(ConfirmedScamConversation)
class ConfirmedScamConversationAdmin(admin.ModelAdmin):

    list_display = (
        'get_short_id',
        'final_risk_score',
        'final_scam_type',
        'confidence_score',
        'pii_redacted',
        'user_consented_training',
        'used_for_training',
        'auto_delete_at',
        'created_at',
    )
    list_filter = (
        'final_scam_type',
        'user_consented_training',
        'used_for_training',
        'pii_redacted',
    )
    readonly_fields = (
        'id', 'created_at', 'auto_delete_at', 'caller_number_hash',
    )
    ordering = ('-created_at',)

    def get_short_id(self, obj):
        return str(obj.id)[:8] + '…'
    get_short_id.short_description = 'ID'