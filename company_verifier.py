import json
import re

class CompanyVerifier:
    def __init__(self, dataset_path='registered_numbers.json'):
        try:
            with open(dataset_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                self.agencies = data.get('verified_agency_numbers', [])
            print(f"Loaded {len(self.agencies)} registered agency numbers")
        except FileNotFoundError:
            print(f"Warning: {dataset_path} not found. Company verification disabled.")
            self.agencies = []
        except Exception as e:
            print(f"Error loading agencies: {e}")
            self.agencies = []
    
    def normalize_phone(self, phone):
        """Normalize phone number for comparison"""
        if not phone:
            return None
        phone = re.sub(r'[\s\-\(\)]', '', str(phone))
        if phone.startswith('0'):
            phone = '+254' + phone[1:]
        elif not phone.startswith('+'):
            phone = '+' + phone
        return phone
    
    def find_agency_by_number(self, phone_number):
        """Find agency by phone number"""
        normalized = self.normalize_phone(phone_number)
        if not normalized:
            return None
        
        for agency in self.agencies:
            agency_num = self.normalize_phone(agency.get('phone_number_raw', ''))
            if agency_num == normalized or agency.get('phone_number_raw') == phone_number:
                return agency
        return None
    
    def find_mentioned_agencies(self, text):
        """Find agency names mentioned in text"""
        if not text:
            return []
        
        text_lower = text.lower()
        mentioned = []
        
        for agency in self.agencies:
            agency_name = agency.get('agency_name', '').lower()
            agency_code = agency.get('agency_code', '').lower()
            
            if agency_name in text_lower or agency_code in text_lower:
                if agency not in mentioned:
                    mentioned.append(agency)
        
        return mentioned
    
    def verify_call(self, phone_number, transcribed_text):
        """Verify if caller number matches claimed agency"""
        result = {
            'is_impersonation': False,
            'warning': None,
            'caller_agency': None,
            'claimed_agencies': [],
            'verification_status': 'unknown'
        }
        
        caller_agency = self.find_agency_by_number(phone_number)
        if caller_agency:
            result['caller_agency'] = caller_agency['agency_name']
            result['verification_status'] = 'verified'
        
        mentioned = self.find_mentioned_agencies(transcribed_text)
        result['claimed_agencies'] = [a['agency_name'] for a in mentioned]
        
        if mentioned and not caller_agency:
            result['is_impersonation'] = True
            result['verification_status'] = 'impersonation'
            agencies_str = ', '.join(result['claimed_agencies'])
            result['warning'] = f"⚠️ IMPERSONATION ALERT: Caller claims to be {agencies_str} but number {phone_number} is NOT registered to them!"
        
        elif mentioned and caller_agency:
            claimed_names = [a['agency_name'] for a in mentioned]
            if caller_agency['agency_name'] not in claimed_names:
                result['is_impersonation'] = True
                result['verification_status'] = 'mismatch'
                result['warning'] = f"⚠️ IMPERSONATION ALERT: Number belongs to {caller_agency['agency_name']} but claims to be {', '.join(claimed_names)}!"
        
        return result
