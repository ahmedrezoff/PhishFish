# whois_checker.py - Domain registration check
import whois
from datetime import datetime

def check_domain(url):
    """Get domain registration information - NO CRASH VERSION"""
    # Extract domain
    try:
        if '://' in url:
            domain = url.split('://')[1]
        else:
            domain = url
        
        # Remove path
        if '/' in domain:
            domain = domain.split('/')[0]
        
        # Remove www
        if domain.startswith('www.'):
            domain = domain[4:]
        
        # Remove port if present
        if ':' in domain:
            domain = domain.split(':')[0]
        
        # Default result
        result = {
            'domain': domain,
            'registrar': 'Not available',
            'creation_date': 'Not available',
            'age_days': 1000,  # Assume old domain
            'is_new': False,
            'status': 'Could not retrieve'
        }
        
        # Try WHOIS with timeout
        try:
            domain_info = whois.whois(domain)
            
            # Get registrar
            if domain_info.registrar:
                if isinstance(domain_info.registrar, list):
                    result['registrar'] = str(domain_info.registrar[0])
                else:
                    result['registrar'] = str(domain_info.registrar)
            
            # Get creation date
            creation_date = None
            if domain_info.creation_date:
                if isinstance(domain_info.creation_date, list):
                    date_str = str(domain_info.creation_date[0])
                else:
                    date_str = str(domain_info.creation_date)
                
                # Try to parse date
                try:
                    # Clean date string
                    date_str = date_str.split('T')[0].split(' ')[0]
                    
                    # Try common formats
                    for fmt in ['%Y-%m-%d', '%d-%b-%Y', '%Y/%m/%d', '%Y.%m.%d', '%b %d %Y', '%d %b %Y']:
                        try:
                            creation_date = datetime.strptime(date_str, fmt)
                            break
                        except:
                            continue
                    
                    if creation_date:
                        result['creation_date'] = creation_date
                        
                        # Calculate age
                        today = datetime.now()
                        if creation_date > today:
                            creation_date = today
                        
                        age_days = (today - creation_date).days
                        result['age_days'] = age_days
                        result['is_new'] = age_days < 180
                except:
                    pass
            
            # Get status
            if domain_info.status:
                if isinstance(domain_info.status, list):
                    result['status'] = ', '.join([str(s) for s in domain_info.status[:2]])
                else:
                    result['status'] = str(domain_info.status)
        
        except Exception as e:
            # WHOIS failed, keep default values
            pass
        
        return result
        
    except Exception as e:
        # Total failure - return minimal info
        return {
            'domain': 'unknown',
            'registrar': 'Check failed',
            'creation_date': 'Not available',
            'age_days': 0,
            'is_new': False,
            'status': 'Error'
        }
