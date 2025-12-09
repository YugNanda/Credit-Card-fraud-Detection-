#!/usr/bin/env python3
"""
💳 CREDIT CARD FRAUD DETECTION SYSTEM 💳
Professional Credit Card Validation & Fraud Detection Tool
Author: Yug 
Version: 1.0.0
"""

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import re
import datetime
import random
import json
import os
from datetime import datetime, timedelta
import threading
import time

class CreditCardValidator:
    """Professional Credit Card Validation and Fraud Detection System"""
    
    def __init__(self):
        self.setup_gui()
        self.fraud_patterns = self.load_fraud_patterns()
        self.transaction_history = []
        
    def load_fraud_patterns(self):
        """Load known fraud patterns and suspicious behaviors"""
        return {
            'suspicious_amounts': [999.99, 1000.00, 499.99, 199.99],
            'blocked_bins': ['123456', '999999', '000000', '666666'],
            'suspicious_merchants': ['DARKWEB', 'ILLEGAL', 'FRAUD'],
            'velocity_limits': {
                'hourly': 5,
                'daily': 20,
                'weekly': 100
            }
        }
    
    def luhn_algorithm(self, card_number):
        """
        Validate credit card number using Luhn Algorithm
        Returns: (is_valid: bool, check_digit: int)
        """
        try:
            # Remove spaces and convert to string
            card_number = str(card_number).replace(' ', '')
            
            if not card_number.isdigit() or len(card_number) < 13:
                return False, 0
            
            # Convert to list of integers
            digits = [int(d) for d in card_number]
            
            # Remove check digit
            check_digit = digits.pop()
            
            # Reverse remaining digits
            digits.reverse()
            
            # Double every second digit
            for i in range(0, len(digits), 2):
                digits[i] *= 2
                if digits[i] > 9:
                    digits[i] = digits[i] // 10 + digits[i] % 10
            
            # Calculate total
            total = sum(digits) + check_digit
            
            # Valid if divisible by 10
            return (total % 10 == 0), check_digit
            
        except Exception as e:
            return False, 0
    
    def detect_card_type(self, card_number):
        """Detect credit card type based on number patterns"""
        card_number = str(card_number).replace(' ', '')
        
        card_patterns = {
            'Visa': r'^4[0-9]{12}(?:[0-9]{3})?$',
            'MasterCard': r'^5[1-5][0-9]{14}$',
            'American Express': r'^3[47][0-9]{13}$',
            'Discover': r'^6(?:011|5[0-9]{2})[0-9]{12}$',
            'JCB': r'^(?:2131|1800|35\d{3})\d{11}$',
            'Diners Club': r'^3(?:0[0-5]|[68][0-9])[0-9]{11}$',
            'Maestro': r'^(?:50|5[6-9]|6[0-9])\d{8,17}$',
            'Verve': r'^(506[01]|507[89]|6500)\d{12,15}$'
        }
        
        for card_type, pattern in card_patterns.items():
            if re.match(pattern, card_number):
                return card_type
        return 'Unknown'
    
    def validate_expiry_date(self, expiry_month, expiry_year):
        """Validate expiry date"""
        try:
            current_date = datetime.now()
            expiry_date = datetime(int(expiry_year), int(expiry_month), 28)
            
            # Check if expiry date is in the future
            if expiry_date > current_date:
                # Check if card is not expired for more than 5 years
                if expiry_date <= current_date + timedelta(days=365*5):
                    return True, "Valid"
                else:
                    return False, "Expiry date too far in future"
            else:
                return False, "Card expired"
                
        except ValueError:
            return False, "Invalid date format"
    
    def validate_cvv(self, cvv, card_type):
        """Validate CVV based on card type"""
        cvv = str(cvv).strip()
        
        if card_type == 'American Express':
            return len(cvv) == 4 and cvv.isdigit()
        else:
            return len(cvv) == 3 and cvv.isdigit()
    
    def fraud_detection_checks(self, card_number, amount=0.0, merchant=""):
        """Advanced fraud detection algorithms"""
        fraud_score = 0
        fraud_reasons = []
        
        card_number = str(card_number).replace(' ', '')
        
        # Check for suspicious BIN (Bank Identification Number)
        bin_number = card_number[:6]
        if bin_number in self.fraud_patterns['blocked_bins']:
            fraud_score += 50
            fraud_reasons.append("Suspicious BIN detected")
        
        # Check for repeated digits (potential test card)
        if len(set(card_number)) < 4:
            fraud_score += 30
            fraud_reasons.append("Too many repeated digits")
        
        # Check for sequential numbers
        if self.has_sequential_pattern(card_number):
            fraud_score += 25
            fraud_reasons.append("Sequential number pattern")
        
        # Check amount patterns
        if amount in self.fraud_patterns['suspicious_amounts']:
            fraud_score += 20
            fraud_reasons.append("Suspicious transaction amount")
        
        # Check merchant
        if any(suspicious in merchant.upper() for suspicious in self.fraud_patterns['suspicious_merchants']):
            fraud_score += 40
            fraud_reasons.append("Suspicious merchant")
        
        # Velocity checks
        velocity_score = self.check_velocity_limits(card_number)
        fraud_score += velocity_score
        if velocity_score > 0:
            fraud_reasons.append("Velocity limits exceeded")
        
        return fraud_score, fraud_reasons
    
    def has_sequential_pattern(self, card_number):
        """Check for sequential number patterns"""
        card_number = str(card_number)
        
        # Check for ascending/descending sequences
        for i in range(len(card_number) - 3):
            sequence = card_number[i:i+4]
            if sequence.isdigit():
                nums = [int(d) for d in sequence]
                if all(nums[j] + 1 == nums[j+1] for j in range(3)):
                    return True
                if all(nums[j] - 1 == nums[j+1] for j in range(3)):
                    return True
        
        return False
    
    def check_velocity_limits(self, card_number):
        """Check transaction velocity limits"""
        # This is a simplified version - in real systems, this would check database
        return random.randint(0, 5)  # Simulate some velocity scoring
    
    def validate_card(self, card_number, expiry_month, expiry_year, cvv, amount=0.0, merchant=""):
        """Complete card validation and fraud detection"""
        results = {
            'card_number': card_number,
            'is_valid': False,
            'card_type': 'Unknown',
            'fraud_score': 0,
            'fraud_reasons': [],
            'expiry_status': 'Unknown',
            'cvv_status': 'Unknown',
            'overall_status': 'REJECTED'
        }
        
        # Basic card number validation
        is_luhn_valid, check_digit = self.luhn_algorithm(card_number)
        results['card_type'] = self.detect_card_type(card_number)
        
        # Expiry validation
        expiry_valid, expiry_msg = self.validate_expiry_date(expiry_month, expiry_year)
        results['expiry_status'] = expiry_msg
        
        # CVV validation
        cvv_valid = self.validate_cvv(cvv, results['card_type'])
        results['cvv_status'] = 'Valid' if cvv_valid else 'Invalid'
        
        # Fraud detection
        fraud_score, fraud_reasons = self.fraud_detection_checks(card_number, amount, merchant)
        results['fraud_score'] = fraud_score
        results['fraud_reasons'] = fraud_reasons
        
        # Overall validation
        if (is_luhn_valid and expiry_valid and cvv_valid and fraud_score < 50):
            results['is_valid'] = True
            results['overall_status'] = 'APPROVED'
        else:
            results['overall_status'] = 'REJECTED'
        
        # Log transaction
        self.log_transaction(results)
        
        return results
    
    def log_transaction(self, results):
        """Log transaction for analysis"""
        transaction = {
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'card_type': results['card_type'],
            'is_valid': results['is_valid'],
            'fraud_score': results['fraud_score'],
            'overall_status': results['overall_status']
        }
        self.transaction_history.append(transaction)
    
    def setup_gui(self):
        """Setup the graphical user interface"""
        self.root = tk.Tk()
        self.root.title("💳 Credit Card Fraud Detection System")
        self.root.geometry("900x700")
        self.root.configure(bg='#f0f0f0')
        
        # Style configuration
        style = ttk.Style()
        style.theme_use('clam')
        
        # Main container
        main_frame = ttk.Frame(self.root, padding="20")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Title
        title_label = tk.Label(main_frame, text="💳 CREDIT CARD VALIDATOR 💳", 
                              font=("Arial", 24, "bold"), fg='#2c3e50', bg='#f0f0f0')
        title_label.grid(row=0, column=0, columnspan=3, pady=20)
        
        # Card Number
        ttk.Label(main_frame, text="Card Number:", font=("Arial", 12)).grid(row=1, column=0, sticky=tk.W, pady=5)
        self.card_number_var = tk.StringVar()
        card_entry = ttk.Entry(main_frame, textvariable=self.card_number_var, width=30, font=("Arial", 12))
        card_entry.grid(row=1, column=1, columnspan=2, pady=5, padx=5)
        
        # Expiry Month
        ttk.Label(main_frame, text="Expiry Month (MM):", font=("Arial", 12)).grid(row=2, column=0, sticky=tk.W, pady=5)
        self.expiry_month_var = tk.StringVar()
        month_entry = ttk.Entry(main_frame, textvariable=self.expiry_month_var, width=10, font=("Arial", 12))
        month_entry.grid(row=2, column=1, pady=5, padx=5)
        
        # Expiry Year
        ttk.Label(main_frame, text="Expiry Year (YYYY):", font=("Arial", 12)).grid(row=3, column=0, sticky=tk.W, pady=5)
        self.expiry_year_var = tk.StringVar()
        year_entry = ttk.Entry(main_frame, textvariable=self.expiry_year_var, width=10, font=("Arial", 12))
        year_entry.grid(row=3, column=1, pady=5, padx=5)
        
        # CVV
        ttk.Label(main_frame, text="CVV:", font=("Arial", 12)).grid(row=4, column=0, sticky=tk.W, pady=5)
        self.cvv_var = tk.StringVar()
        cvv_entry = ttk.Entry(main_frame, textvariable=self.cvv_var, width=10, font=("Arial", 12), show="*")
        cvv_entry.grid(row=4, column=1, pady=5, padx=5)
        
        # Amount (optional)
        ttk.Label(main_frame, text="Amount ($):", font=("Arial", 12)).grid(row=5, column=0, sticky=tk.W, pady=5)
        self.amount_var = tk.StringVar(value="0.00")
        amount_entry = ttk.Entry(main_frame, textvariable=self.amount_var, width=10, font=("Arial", 12))
        amount_entry.grid(row=5, column=1, pady=5, padx=5)
        
        # Merchant (optional)
        ttk.Label(main_frame, text="Merchant:", font=("Arial", 12)).grid(row=6, column=0, sticky=tk.W, pady=5)
        self.merchant_var = tk.StringVar(value="Test Merchant")
        merchant_entry = ttk.Entry(main_frame, textvariable=self.merchant_var, width=20, font=("Arial", 12))
        merchant_entry.grid(row=6, column=1, columnspan=2, pady=5, padx=5)
        
        # Validate Button
        validate_btn = tk.Button(main_frame, text="🔍 VALIDATE CARD", command=self.validate_card_gui,
                                bg='#27ae60', fg='white', font=("Arial", 14, "bold"),
                                padx=20, pady=10, cursor='hand2')
        validate_btn.grid(row=7, column=0, columnspan=3, pady=20)
        
        # Clear Button
        clear_btn = tk.Button(main_frame, text="🗑️ CLEAR", command=self.clear_fields,
                             bg='#e74c3c', fg='white', font=("Arial", 12),
                             padx=15, pady=5, cursor='hand2')
        clear_btn.grid(row=8, column=0, columnspan=3, pady=10)
        
        # Results Text Area
        self.results_text = scrolledtext.ScrolledText(main_frame, height=15, width=70,
                                                     font=("Courier", 10), bg='#f8f9fa')
        self.results_text.grid(row=9, column=0, columnspan=3, pady=20, padx=10)
        
        # Status Bar
        self.status_var = tk.StringVar(value="Ready")
        status_bar = tk.Label(self.root, textvariable=self.status_var, bd=1, relief=tk.SUNKEN,
                             anchor=tk.W, bg='#ecf0f1', fg='#2c3e50')
        status_bar.grid(row=1, column=0, sticky=(tk.W, tk.E))
        
        # Configure grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
    
    def validate_card_gui(self):
        """Validate card from GUI input"""
        try:
            self.status_var.set("Validating...")
            self.root.update()
            
            # Get input values
            card_number = self.card_number_var.get().strip()
            expiry_month = self.expiry_month_var.get().strip()
            expiry_year = self.expiry_year_var.get().strip()
            cvv = self.cvv_var.get().strip()
            amount = float(self.amount_var.get() or 0.0)
            merchant = self.merchant_var.get().strip()
            
            # Validate required fields
            if not all([card_number, expiry_month, expiry_year, cvv]):
                messagebox.showerror("Error", "Please fill in all required fields!")
                self.status_var.set("Validation failed")
                return
            
            # Perform validation
            results = self.validate_card(card_number, expiry_month, expiry_year, cvv, amount, merchant)
            
            # Display results
            self.display_results(results)
            
            self.status_var.set("Validation complete")
            
        except ValueError as e:
            messagebox.showerror("Error", f"Invalid input: {str(e)}")
            self.status_var.set("Validation failed")
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {str(e)}")
            self.status_var.set("Validation failed")
    
    def display_results(self, results):
        """Display validation results in the text area"""
        self.results_text.delete(1.0, tk.END)
        
        # Header
        self.results_text.insert(tk.END, "="*60 + "\n")
        self.results_text.insert(tk.END, "           💳 VALIDATION RESULTS 💳\n")
        self.results_text.insert(tk.END, "="*60 + "\n\n")
        
        # Card Information
        self.results_text.insert(tk.END, f"Card Number: {results['card_number']}\n")
        self.results_text.insert(tk.END, f"Card Type: {results['card_type']}\n")
        self.results_text.insert(tk.END, f"Expiry Status: {results['expiry_status']}\n")
        self.results_text.insert(tk.END, f"CVV Status: {results['cvv_status']}\n")
        
        # Validation Status
        if results['is_valid']:
            self.results_text.insert(tk.END, f"Card Validation: ✅ VALID\n", "valid")
        else:
            self.results_text.insert(tk.END, f"Card Validation: ❌ INVALID\n", "invalid")
        
        # Fraud Detection
        self.results_text.insert(tk.END, f"\nFraud Score: {results['fraud_score']}/100\n")
        
        if results['fraud_reasons']:
            self.results_text.insert(tk.END, "Fraud Alerts:\n", "warning")
            for reason in results['fraud_reasons']:
                self.results_text.insert(tk.END, f"  ⚠️  {reason}\n", "warning")
        else:
            self.results_text.insert(tk.END, "✅ No fraud indicators detected\n", "valid")
        
        # Overall Status
        status_color = "valid" if results['overall_status'] == 'APPROVED' else "invalid"
        self.results_text.insert(tk.END, f"\nOverall Status: {results['overall_status']}\n", status_color)
        
        # Recommendations
        self.results_text.insert(tk.END, "\n" + "="*60 + "\n")
        self.results_text.insert(tk.END, "📋 RECOMMENDATIONS:\n")
        
        if results['overall_status'] == 'APPROVED':
            self.results_text.insert(tk.END, "✅ Card is safe to proceed with transaction\n")
            self.results_text.insert(tk.END, "✅ All security checks passed\n")
        else:
            self.results_text.insert(tk.END, "❌ Do not proceed with this transaction\n")
            if results['fraud_score'] > 50:
                self.results_text.insert(tk.END, "🚨 High fraud risk detected!\n")
                self.results_text.insert(tk.END, "📞 Contact card issuer immediately\n")
        
        # Configure text tags
        self.results_text.tag_config("valid", foreground="#27ae60", font=("Courier", 10, "bold"))
        self.results_text.tag_config("invalid", foreground="#e74c3c", font=("Courier", 10, "bold"))
        self.results_text.tag_config("warning", foreground="#f39c12", font=("Courier", 10))
    
    def clear_fields(self):
        """Clear all input fields"""
        self.card_number_var.set("")
        self.expiry_month_var.set("")
        self.expiry_year_var.set("")
        self.cvv_var.set("")
        self.amount_var.set("0.00")
        self.merchant_var.set("Test Merchant")
        self.results_text.delete(1.0, tk.END)
        self.status_var.set("Ready")
    
    def run(self):
        """Run the application"""
        self.root.mainloop()

def main():
    """Main function to run the Credit Card Fraud Detection System"""
    print("💳 Starting Credit Card Fraud Detection System...")
    print("="*50)
    
    # Create and run the application
    app = CreditCardValidator()
    app.run()

if __name__ == "__main__":
    main()
