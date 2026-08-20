"""
Analysis engine (Phase 4): pure, read-only functions over plain FortiOS
policy/object dicts. No I/O, no adapter/repository imports -- fetching the
live data is AnalysisService's job (services/analysis_service.py); these
modules only ever see the lists it hands them.
"""
