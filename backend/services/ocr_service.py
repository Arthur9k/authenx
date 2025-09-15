# backend/services/ocr_service.py

import re
from typing import Dict, Optional, Tuple, List, Any
import pytesseract
import cv2
import numpy as np

### ADDED: Advanced Image Preprocessing Utilities ###
# These functions handle scanned/rotated documents before OCR.
def _correct_orientation(image: np.ndarray) -> np.ndarray:
    try:
        osd = pytesseract.image_to_osd(image, output_type=pytesseract.Output.DICT)
        rotation = osd.get('rotate', 0)
        if rotation != 0:
            (h, w) = image.shape[:2]
            center = (w // 2, h // 2)
            M = cv2.getRotationMatrix2D(center, -rotation, 1.0)
            image = cv2.warpAffine(image, M, (w, h), flags=cv2.INTER_CUBIC, borderMode=cv2.BORDER_REPLICATE)
    except Exception:
        pass
    return image

def _deskew(image: np.ndarray) -> np.ndarray:
    try:
        gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
        gray = cv2.bitwise_not(gray)
        thresh = cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY | cv2.THRESH_OTSU)[1]
        coords = np.column_stack(np.where(thresh > 0))
        angle = cv2.minAreaRect(coords)[-1]
        angle = -(90 + angle) if angle < -45 else -angle
        if abs(angle) > 0.5:
            (h, w) = image.shape[:2]
            center = (w // 2, h // 2)
            M = cv2.getRotationMatrix2D(center, angle, 1.0)
            image = cv2.warpAffine(image, M, (w, h), flags=cv2.INTER_CUBIC, borderMode=cv2.BORDER_REPLICATE)
    except Exception:
        pass
    return image

### ADDED: The two-function architecture required by your verify.py ###

def get_text_for_classification(image: np.ndarray) -> str:
    """Performs a lightweight OCR pass for quick document classification."""
    if image is None: return ""
    gray_image = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY) if len(image.shape) == 3 else image
    try:
        custom_config = r'--oem 3 --psm 3'
        text = pytesseract.image_to_string(gray_image, lang='eng+hin', config=custom_config, timeout=10)
        return text
    except Exception as e:
        print(f"Error during classification OCR: {e}")
        return ""

def extract_structured_data(image: np.ndarray) -> Tuple[str, Dict[str, Any]]:
    """
    Performs full preprocessing and uses your original AdvancedOcrExtractor logic.
    This function now correctly returns both the full text and the extracted data dictionary.
    """
    if image is None: return "", {}
    
    gray_image = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
    
    # Apply robust preprocessing
    oriented_image = _correct_orientation(gray_image)
    deskewed_image = _deskew(oriented_image)
    
    try:
        # Use multilingual OCR
        custom_config = r'--oem 3 --psm 4'
        raw_text = pytesseract.image_to_string(deskewed_image, lang='eng+hin', config=custom_config)
    except pytesseract.TesseractNotFoundError:
        print("TESSERACT ERROR: 'tesseract' is not installed or not in your PATH.")
        return "", {}

    # Instantiate your proven extractor class with the preprocessed, multilingual text
    extractor = AdvancedOcrExtractor(raw_text)
    extracted_data = extractor.extract_all()

    return raw_text, extracted_data

### KEPT: Your original, working AdvancedOcrExtractor class, with minor enhancements ###
class AdvancedOcrExtractor:
    def __init__(self, raw_text: str):
        self.raw_text = raw_text
        self.lines = [line.strip() for line in raw_text.split('\n') if line.strip()]
        self.text_lower = raw_text.lower()

    ### ENHANCED: Your keywords with Hindi support ###
    FIELD_KEYWORDS = {
        'university': ['university', 'vidyalaya', 'institute', 'board', 'परिषद', 'बोर्ड', 'विश्वविद्यालय'],
        'name': ['name of the student', 'name', 'student name', 'certify that', 'NAME OF STUDENT'],
        'father_name': ["father's name", 'father', 'पिता', 's/o', 'son of'],
        'mother_name': ["mother's name", 'mother', 'माता', 'd/o', 'daughter of'],
        'roll_no': ['roll no', 'roll number', 'seat no', 'अनुक्रमांक'],
        'enrolment_no': ['enrollment no', 'enrolment no', 'registration no', 'regd. no.'],
        'course': ['program', 'course', 'degree of', 'branch'],
        'session': ['session', 'academic year', 'year'],
        'result': ['result', 'cgpa', 'sgpa', 'percentage', 'division'],
        'semester': ['semester', 'sem', 'Semester I','semester II'],
        'sgpa': ['sgpa', 'semester grade point average'],
        'dob': ['Date of Birth', 'DOB', 'जन्म तिथि'],
        'issue_date': ['date of issue','declared on', 'result declared on','date of declaration' 'दिनांक']
    }

    REGEX_PATTERNS = {
        'session': re.compile(r'(\d{4}\s*-\s*\d{2,4})'),
        'cgpa': re.compile(r'(?:cumulative grade point average|cgpa)\s*[:\-–—]?\s*(\d\.\d{1,2})', re.I),
        'percentage': re.compile(r'(\d{2,3}(?:\.\d{1,2})?%)'),
        'dob': re.compile(r'.*?(\d{2}[/-]\d{2}[/-]\d{2,4})'), # A robust DOB regex
        'issue_date': re.compile(r'(\d{1,2}[\s./-](?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\w*[\s./-]\d{2,4}|\d{1,2}[./-]\d{1,2}[./-]\d{2,4})', re.IGNORECASE)
    }

    ### KEPT: Your original working functions ###
    def _clean_value(self, value: str) -> str:
        if not value: return ""
        cleaned = re.sub(r'^[^\w\d]+', '', value).strip()
        return cleaned

    # In backend/services/ocr_service.py

# Replace the entire old _extract_by_keyword function with this one.
    # In backend/services/ocr_service.py

# Replace the entire old _extract_by_keyword function with this one.
    def _extract_by_keyword(self, field_name: str, text: str) -> Optional[str]:
        keywords = self.FIELD_KEYWORDS.get(field_name, [])
        keywords.sort(key=len, reverse=True)
        lines = text.split('\n')
        
        for i, line in enumerate(lines):
            found_keyword = None
            for keyword in keywords:
                if re.search(r'\b' + re.escape(keyword) + r'\b', line, re.IGNORECASE):
                    found_keyword = keyword
                    break

            if found_keyword:
                # --- THIS IS THE NEW, SMARTER LOGIC ---
                
                # 1. If this is a date field, we use a more robust method.
                if field_name in ['issue_date', 'dob']:
                    date_pattern = self.REGEX_PATTERNS.get(field_name)
                    # We search the ENTIRE LINE for something that looks like a date.
                    if date_pattern:
                        match = date_pattern.search(line)
                        if match:
                            # If we find a clean date pattern, we return ONLY that part.
                            # This ignores extra words like "declared on" and messy times.
                            return match.group(1).strip()
                
                # 2. For all other fields, we use the reliable split method.
                parts = re.split(r'\b' + re.escape(found_keyword) + r'\b', line, maxsplit=1, flags=re.IGNORECASE)
                value_part = parts[1] if len(parts) > 1 else ""

                if value_part.strip():
                    return self._clean_value(value_part)
                elif i + 1 < len(lines):
                    next_line_text = lines[i+1].strip()
                    if next_line_text and not any(kw in next_line_text.lower() for kw in sum(self.FIELD_KEYWORDS.values(), [])):
                        return self._clean_value(next_line_text)

        return None
    def _extract_all_names(self) -> Dict[str, Optional[str]]:
        names = {'name': None, 'father_name': None, 'mother_name': None}
        names['father_name'] = self._extract_by_keyword('father_name', self.raw_text)
        names['mother_name'] = self._extract_by_keyword('mother_name', self.raw_text)
        
        # Keep your original logic for finding the student's name
        student_name_lines = []
        father_mother_keywords = self.FIELD_KEYWORDS['father_name'] + self.FIELD_KEYWORDS['mother_name']
        for line in self.lines:
            if not any(re.search(r'\b' + re.escape(kw) + r'\b', line, re.I) for kw in father_mother_keywords):
                student_name_lines.append(line)
        names['name'] = self._extract_by_keyword('name', "\n".join(student_name_lines))
        return names

    def _extract_subjects_and_marks(self) -> List[Dict[str, str]]:
        # Your original logic is kept
        subjects = []
        table_row_pattern = re.compile(r'([A-Z&\s]{5,})\s+(\d{2,3})\s+(\d{2,3})')
        for line in self.lines:
            if any(kw in line.lower() for kw in ['subject', 'marks', 'grade', 'max', 'min']):
                continue
            match = table_row_pattern.search(line)
            if match:
                subject, marks_obt, marks_max = match.groups()
                subjects.append({
                    'subject': subject.strip(),
                    'marks_obtained': marks_obt.strip(),
                    'max_marks': marks_max.strip()
                })
        return subjects

    def extract_all(self) -> Dict[str, Any]:
        # Your original orchestration logic, with a robust DOB fallback
        results = {}
        results.update(self._extract_all_names())
        results['university'] = self._extract_by_keyword('university', self.raw_text)
        if results.get('university') and 'internet generated' in results['university'].lower():
    # Discard the bad result and try to find a better one from the top lines
            for line in self.lines[:4]:
                if 'university' in line.lower() and 'internet' not in line.lower():
                    results['university'] = self._clean_value(line)
                    break
            else:
                # If no better option is found, set it to None
                results['university'] = None
        results['roll_no'] = self._extract_by_keyword('roll_no', self.raw_text)
        
            # 1. First, get the potentially messy date string using our existing method.
        messy_date_string = self._extract_by_keyword('issue_date', self.raw_text)
        
        # 2. Now, the "Cleanup Crew" steps in with the "white-out".
        if messy_date_string:
            # This regex finds any part that looks like a time (e.g., HH:MM, HH:MM PM) and removes it.
            time_pattern = re.compile(r'\s*\d{1,2}:\d{2}(:\d{2})?\s*(AM|PM)?', re.IGNORECASE)
            clean_date = time_pattern.sub('', messy_date_string).strip()
            
            # We store the cleaned-up date string.
            results['issue_date'] = clean_date
                
        # --- END OF NEW DATE LOGIC ---
        # Robust DOB check: use keyword method first, then fallback to regex search
        results['dob'] = self._extract_by_keyword('dob', self.raw_text)
        if not results.get('dob'):
            dob_match = re.search(self.REGEX_PATTERNS['dob'], self.raw_text)
            if dob_match:
                results['dob'] = dob_match.group(1)


        #results['subjects'] = self._extract_subjects_and_marks()
        # Keep the rest of your original extraction logic
        results['enrolment_no'] = self._extract_by_keyword('enrolment_no', self.raw_text)
        results['course'] = self._extract_by_keyword('course', self.raw_text)
        results['session'] = self._extract_by_keyword('session', self.raw_text)
        results['result'] = self._extract_by_keyword('result', self.raw_text)

        for key, value in results.items():
            if isinstance(value, str):
                results[key] = self._clean_value(value)
        return {k: v for k, v in results.items() if v}