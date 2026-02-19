from django.db import models

# This app doesn't need its own models
# It queries data from other apps:
# - User (authentication)
# - CallSession, RiskAlert (real_time_detection)
# - PhoneNumberActive, ScamIncident (scam_database)
# - ReporterCredibility (scam_database)

# All analytics are computed on-the-fly from existing data
