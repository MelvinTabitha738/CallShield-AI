# backend_apps/scam_database/admin.py

from django.contrib import admin
from .models import (
    PhoneNumberActive,
    PhoneNumberArchived,
    ScamIncident,
    ScamEvidence,
    ReporterCredibility
)


@admin.register(PhoneNumberActive)
class PhoneNumberActiveAdmin(admin.ModelAdmin):
    list_display = (
        'get_hash_display',
        'risk_score',
        'get_risk_level',
        'primary_scam_type',
        'report_count',
        'verified_reports',
        'last_reported_at'
    )
    list_filter = ('primary_scam_type', 'eligible_for_archive')
    search_fields = ('phone_number_hash',)
    readonly_fields = (
        'phone_number_hash',
        'first_reported_at',
        'last_reported_at',
        'last_decay_calculated',
        'get_full_hash'
    )
    ordering = ('-risk_score', '-last_reported_at')
    
    fieldsets = (
        ('Phone Number (Hashed)', {
            'fields': ('get_full_hash', 'phone_number_hash'),
            'description': 'Privacy-protected: Only hash stored'
        }),
        ('Risk Assessment', {
            'fields': ('risk_score', 'primary_scam_type', 'decay_factor')
        }),
        ('Statistics', {
            'fields': (
                'report_count',
                'verified_reports',
                'false_positive_count',
                'total_victims_estimated',
                'total_amount_lost_estimated'
            )
        }),
        ('Timestamps', {
            'fields': (
                'first_reported_at',
                'last_reported_at',
                'last_incident_at',
                'last_decay_calculated'
            )
        }),
        ('Archive Status', {
            'fields': ('eligible_for_archive', 'days_since_last_incident')
        }),
    )
    
    def get_hash_display(self, obj):
        return obj.get_display_hash(obj.phone_number_hash)
    get_hash_display.short_description = 'Phone Hash'
    
    def get_full_hash(self, obj):
        return obj.phone_number_hash
    get_full_hash.short_description = 'Full Hash (SHA-256)'


@admin.register(PhoneNumberArchived)
class PhoneNumberArchivedAdmin(admin.ModelAdmin):
    list_display = (
        'get_hash_display',
        'risk_score',
        'historical_peak_risk',
        'historical_report_count',
        'reactivation_count',
        'archived_at'
    )
    list_filter = ('historical_scam_type', 'reactivation_count')
    search_fields = ('phone_number_hash',)
    readonly_fields = ('phone_number_hash', 'archived_at', 'get_full_hash')
    ordering = ('-archived_at',)
    
    def get_hash_display(self, obj):
        return obj.get_display_hash(obj.phone_number_hash)
    get_hash_display.short_description = 'Phone Hash'
    
    def get_full_hash(self, obj):
        return obj.phone_number_hash
    get_full_hash.short_description = 'Full Hash (SHA-256)'


@admin.register(ScamIncident)
class ScamIncidentAdmin(admin.ModelAdmin):
    list_display = (
        'get_hash_display',
        'scam_type',
        'severity',
        'evidence_quality',
        'source',
        'verified',
        'incident_datetime',
        'reported_by'
    )
    list_filter = (
        'scam_type',
        'source',
        'verified',
        'evidence_quality'
    )
    search_fields = ('phone_number_hash',)
    readonly_fields = ('phone_number_hash', 'reported_at', 'get_full_hash')
    ordering = ('-incident_datetime',)
    
    fieldsets = (
        ('Phone Number (Hashed)', {
            'fields': ('get_full_hash', 'phone_number_hash')
        }),
        ('Incident Details', {
            'fields': ('scam_type', 'severity', 'source', 'incident_datetime')
        }),
        ('Reporter', {
            'fields': ('reported_by',)
        }),
        ('Evidence', {
            'fields': ('has_recording', 'has_transcript', 'evidence_quality')
        }),
        ('Verification', {
            'fields': ('verified', 'verified_by_ai', 'confidence_score')
        }),
        ('Impact', {
            'fields': ('victim_lost_money', 'amount_lost', 'region')
        }),
    )
    
    def get_hash_display(self, obj):
        return obj.get_display_hash(obj.phone_number_hash)
    get_hash_display.short_description = 'Phone Hash'
    
    def get_full_hash(self, obj):
        return obj.phone_number_hash
    get_full_hash.short_description = 'Full Hash (SHA-256)'


@admin.register(ScamEvidence)
class ScamEvidenceAdmin(admin.ModelAdmin):
    list_display = (
        'incident',
        'get_evidence_summary',
        'user_confidence_level',
        'verified_by_moderator',
        'submitted_at'
    )
    list_filter = (
        'verified_by_moderator',
        'user_consented_storage',
        'user_consented_training',
        'narrative_language'
    )
    search_fields = ('incident__phone_number_hash', 'narrative')
    readonly_fields = ('submitted_at', 'processed_at', 'auto_delete_at')
    
    fieldsets = (
        ('Related Incident', {
            'fields': ('incident',)
        }),
        ('Text Evidence', {
            'fields': ('narrative', 'narrative_language')
        }),
        ('Audio Evidence', {
            'fields': ('audio_file', 'audio_duration_seconds', 'audio_anonymized')
        }),
        ('Transcript', {
            'fields': ('transcript', 'transcript_source', 'transcript_pii_redacted')
        }),
        ('Screenshots', {
            'fields': ('screenshot_1', 'screenshot_2', 'screenshot_3')
        }),
        ('Metadata', {
            'fields': ('call_duration_seconds', 'user_confidence_level', 'tags')
        }),
        ('Verification', {
            'fields': ('verified_by_moderator', 'moderator_notes')
        }),
        ('Consent & Privacy', {
            'fields': (
                'user_consented_storage',
                'user_consented_training',
                'auto_delete_at'
            )
        }),
        ('Timestamps', {
            'fields': ('submitted_at', 'processed_at')
        }),
    )
    
    def get_evidence_summary(self, obj):
        parts = []
        if obj.narrative:
            parts.append('📝Text')
        if obj.audio_file:
            parts.append('🎵Audio')
        if obj.transcript:
            parts.append('📄Transcript')
        if obj.screenshot_1 or obj.screenshot_2 or obj.screenshot_3:
            parts.append('📸Screenshots')
        return ' | '.join(parts) if parts else 'No evidence'
    get_evidence_summary.short_description = 'Evidence Types'


@admin.register(ReporterCredibility)
class ReporterCredibilityAdmin(admin.ModelAdmin):
    list_display = (
        'user',
        'credibility_tier',
        'credibility_score',
        'total_reports',
        'verified_reports',
        'false_reports'
    )
    list_filter = ('credibility_tier',)
    search_fields = ('user__phone_number', 'user__display_name')
    readonly_fields = ('first_report_at', 'last_report_at')
    
    fieldsets = (
        ('User', {
            'fields': ('user',)
        }),
        ('Statistics', {
            'fields': (
                'total_reports',
                'verified_reports',
                'false_reports',
                'pending_reports'
            )
        }),
        ('Credibility', {
            'fields': ('credibility_score', 'credibility_tier')
        }),
        ('Timestamps', {
            'fields': ('first_report_at', 'last_report_at')
        }),
    )