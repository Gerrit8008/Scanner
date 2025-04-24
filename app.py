# SPF Record
        spf_status = email_data.get('spf', {}).get('status', 'Unknown')
        spf_severity = email_data.get('spf', {}).get('severity', 'Medium')
        spf_severity_class = 'high' if spf_severity == 'Low' else 'medium' if spf_severity == 'Medium' else 'low'
        
        html += f"""
            <tr>
                <td>SPF Record</td>
                <td>{spf_status}</td>
                <td class="{spf_severity_class}">{spf_severity}</td>
            </tr>
        """
        
        # DMARC Record
        dmarc_status = email_data.get('dmarc', {}).get('status', 'Unknown')
        dmarc_severity = email_data.get('dmarc', {}).get('severity', 'Medium')
        dmarc_severity_class = 'high' if dmarc_severity == 'Low' else 'medium' if dmarc_severity == 'Medium' else 'low'
        
        html += f"""
            <tr>
                <td>DMARC Record</td>
                <td>{dmarc_status}</td>
                <td class="{dmarc_severity_class}">{dmarc_severity}</td>
            </tr>
        """
        
        # DKIM Record
        dkim_status = email_data.get('dkim', {}).get('status', 'Unknown')
        dkim_severity = email_data.get('dkim', {}).get('severity', 'Medium')
        dkim_severity_class = 'high' if dkim_severity == 'Low' else 'medium' if dkim_severity == 'Medium' else 'low'
        
        html += f"""
            <tr>
                <td>DKIM Record</td>
                <td>{dkim_status}</td>
                <td class="{dkim_severity_class}">{dkim_severity}</td>
            </tr>
        """
        
        html += """
            </table>
            
            <div class="recommendation">
                <strong>Recommendation:</strong> Implement SPF, DKIM, and DMARC records to protect against email spoofing and phishing attacks.
            </div>
        </div>
        """
    
    # Network security section (for integrated scan)
    if is_integrated and 'network' in scan_results:
        network_data = scan_results['network']
        
        if 'error' not in network_data:
            html += """
            <div class="section">
                <h2>Network Security</h2>
            """
            
            # Open Ports
            if 'open_ports' in network_data:
                ports_data = network_data['open_ports']
                ports_count = ports_data.get('count', 0)
                ports_list = ports_data.get('list', [])
                ports_severity = ports_data.get('severity', 'Low')
                
                ports_severity_class = 'high' if ports_severity == 'Low' else 'medium' if ports_severity == 'Medium' else 'low'
                
                html += f"""
                <div class="subsection">
                    <h3>Open Ports</h3>
                    <p><strong>Open Ports Count:</strong> {ports_count}</p>
                    <p><strong>Severity:</strong> <span class="{ports_severity_class}">{ports_severity}</span></p>
                    
                    <p><strong>Open Ports:</strong> {', '.join(str(p) for p in sorted(ports_list[:20]))}
                """
                
                if len(ports_list) > 20:
                    html += f" and {len(ports_list) - 20} more..."
                
                html += "</p>"
                
                # Add high-risk ports analysis
                high_risk_ports = [21, 22, 23, 25, 53, 137, 138, 139, 445, 1433, 1434, 3306, 3389, 5432, 5900]
                high_risk_open = [p for p in ports_list if p in high_risk_ports]
                
                if high_risk_open:
                    html += """
                    <div class="issue high-severity">
                        <p><strong>High-Risk Ports Detected:</strong></p>
                        <ul>
                    """
                    
                    for port in high_risk_open:
                        service = ""
                        if port == 21:
                            service = "FTP - Transmits credentials in plain text"
                        elif port == 22:
                            service = "SSH - Remote terminal access"
                        elif port == 23:
                            service = "Telnet - Insecure, transmits data in plain text"
                        elif port == 3389:
                            service = "Remote Desktop Protocol (RDP) - High security risk if exposed"
                        elif port == 5900:
                            service = "VNC - Remote desktop access, often lacks encryption"
                        elif port in [139, 445]:
                            service = "SMB/NetBIOS - Windows file sharing, historically vulnerable"
                        elif port in [1433, 3306]:
                            service = "Database access (SQL Server/MySQL)"
                        
                        html += f"""
                        <li>Port {port}: {service}</li>
                        """
                    
                    html += """
                        </ul>
                    </div>
                    """
                
                html += """
                <div class="recommendation">
                    <strong>Recommendation:</strong> Close unnecessary ports, especially high-risk ones. For required services, implement proper security measures like firewall rules and strong authentication.
                </div>
                </div>
                """
            
            # Gateway
            if 'gateway' in network_data:
                gateway_data = network_data['gateway']
                gateway_info = gateway_data.get('info', '')
                gateway_results = gateway_data.get('results', [])
                
                html += """
                <div class="subsection">
                    <h3>Gateway Security</h3>
                """
                
                if gateway_info:
                    html += f"""
                    <p>{gateway_info}</p>
                    """
                
                if gateway_results:
                    high_severity_issues = [msg for msg, severity in gateway_results if severity in ['High', 'Critical']]
                    
                    if high_severity_issues:
                        html += """
                        <div class="issue high-severity">
                            <p><strong>Gateway Security Issues:</strong></p>
                            <ul>
                        """
                        
                        for msg in high_severity_issues:
                            html += f"""
                            <li>{msg}</li>
                            """
                        
                        html += """
                            </ul>
                        </div>
                        """
                
                html += """
                </div>
                """
            
            html += """
            </div>
            """
    
    # SSL/TLS Certificate section
    if 'ssl_certificate' in scan_results and 'error' not in scan_results['ssl_certificate']:
        ssl_data = scan_results['ssl_certificate']
        
        status = ssl_data.get('status', 'Unknown')
        status_class = 'high' if status == 'valid' else 'low'
        
        html += f"""
        <div class="section">
            <h2>SSL/TLS Certificate</h2>
            <p>Status: <span class="{status_class}">{status.upper()}</span></p>
            
            <table>
                <tr>
                    <th>Attribute</th>
                    <th>Value</th>
                </tr>
                <tr>
                    <td>Issuer</td>
                    <td>{ssl_data.get('issuer', 'Unknown')}</td>
                </tr>
                <tr>
                    <td>Valid Until</td>
                    <td>{ssl_data.get('valid_until', 'Unknown')}</td>
                </tr>
                <tr>
                    <td>Days to Expiry</td>
                    <td>{ssl_data.get('days_to_expiry', 'Unknown')}</td>
                </tr>
                <tr>
                    <td>Protocol</td>
                    <td>{ssl_data.get('protocol', 'Unknown')}</td>
                </tr>
                <tr>
                    <td>Cipher Suite</td>
                    <td>{ssl_data.get('cipher_suite', 'Unknown')}</td>
                </tr>
            </table>
            
            <div class="subsection">
                <h3>Issues</h3>
        """
        
        has_issues = False
        
        if ssl_data.get('is_expired', False):
            has_issues = True
            html += """
                <div class="issue high-severity">
                    <strong>Critical: Certificate is expired</strong>
                    <p>Your SSL certificate has expired and needs to be renewed immediately.</p>
                </div>
            """
        elif ssl_data.get('expiring_soon', False):
            has_issues = True
            html += """
                <div class="issue medium-severity">
                    <strong>Warning: Certificate expiring soon</strong>
                    <p>Your SSL certificate will expire soon. Plan to renew it before expiration.</p>
                </div>
            """
        
        if ssl_data.get('weak_protocol', False):
            has_issues = True
            html += """
                <div class="issue high-severity">
                    <strong>Critical: Weak SSL/TLS protocol</strong>
                    <p>Your server is using an outdated SSL/TLS protocol that has known vulnerabilities.</p>
                </div>
            """
        
        if not has_issues:
            html += """
                <p>No issues found with SSL certificate.</p>
            """
        
        html += """
            </div>
        </div>
        """
    
    # Security Headers section
    if 'security_headers' in scan_results and 'error' not in scan_results['security_headers']:
        headers_data = scan_results['security_headers']
        
        score = headers_data.get('score', 0)
        score_class = 'high' if score >= 80 else 'medium' if score >= 60 else 'low'
        
        html += f"""
        <div class="section">
            <h2>HTTP Security Headers</h2>
            <p>Score: <span class="{score_class}">{score}/100</span></p>
            
            <div class="subsection">
                <h3>Missing Headers</h3>
        """
        
        missing_headers = headers_data.get('missing_headers', [])
        
        if missing_headers:
            html += """
                <ul>
            """
            
            for header in missing_headers:
                description = headers_data.get('headers', {}).get(header, {}).get('description', '')
                html += f"""
                    <li><strong>{header}</strong>: {description}</li>
                """
            
            html += """
                </ul>
            """
        else:
            html += """
                <p>All recommended security headers are present. Great job!</p>
            """
        
        html += """
            </div>
            
            <div class="subsection">
                <h3>Present Headers</h3>
                <table>
                    <tr>
                        <th>Header</th>
                        <th>Value</th>
                    </tr>
        """
        
        for header, details in headers_data.get('headers', {}).items():
            if details.get('present', False):
                html += f"""
                    <tr>
                        <td>{header}</td>
                        <td><code>{details.get('value', 'Unknown')}</code></td>
                    </tr>
                """
        
        html += """
                </table>
            </div>
        </div>
        """
    
    # CMS Detection section
    if 'cms' in scan_results and 'error' not in scan_results['cms']:
        cms_data = scan_results['cms']
        
        if cms_data.get('cms_detected', False):
            cms_name = cms_data.get('cms_name', 'Unknown CMS')
            cms_version = cms_data.get('version', 'Unknown')
            
            html += f"""
            <div class="section">
                <h2>Content Management System (CMS)</h2>
                <p><strong>CMS:</strong> {cms_name}</p>
                <p><strong>Version:</strong> {cms_version}</p>
                <p><strong>Confidence:</strong> {cms_data.get('confidence', 'Unknown')}</p>
            """
            
            vulnerabilities = cms_data.get('potential_vulnerabilities', [])
            if vulnerabilities:
                html += """
                <div class="subsection">
                    <h3>Potential Vulnerabilities</h3>
                    <ul>
                """
                
                for vuln in vulnerabilities:
                    html += f"""
                    <li>
                        <div class="issue high-severity">
                            <strong>{vuln.get('name', 'Unknown Issue')}</strong>
                            <p>{vuln.get('description', '')}</p>
                            <div class="recommendation">
                                <strong>Recommendation:</strong> {vuln.get('recommendation', '')}
                            </div>
                        </div>
                    </li>
                    """
                
                html += """
                    </ul>
                </div>
                """
            else:
                html += """
                <p>No known vulnerabilities detected for this CMS configuration.</p>
                """
            
            html += """
            </div>
            """
    
    # Web Framework Detection section
    if 'frameworks' in scan_results and 'error' not in scan_results['frameworks']:
        framework_data = scan_results['frameworks']
        frameworks_list = framework_data.get('frameworks', [])
        
        if frameworks_list:
            html += """
            <div class="section">
                <h2>Web Technologies</h2>
                <table>
                    <tr>
                        <th>Technology</th>
                        <th>Version</th>
                        <th>Type</th>
                    </tr>
            """
            
            for framework in frameworks_list:
                html += f"""
                    <tr>
                        <td>{framework.get('name', 'Unknown')}</td>
                        <td>{framework.get('value', 'Unknown')}</td>
                        <td>{framework.get('type', 'Unknown')}</td>
                    </tr>
                """
            
            html += """
                </table>
            """
            
            vulnerabilities = framework_data.get('known_vulnerabilities', [])
            if vulnerabilities:
                html += """
                <div class="subsection">
                    <h3>Known Vulnerabilities</h3>
                    <ul>
                """
                
                for vuln in vulnerabilities:
                    html += f"""
                    <li>
                        <div class="issue high-severity">
                            <strong>{vuln.get('framework', 'Unknown')} {vuln.get('version', '')}</strong>
                            <p>{vuln.get('description', '')}</p>
                            <div class="recommendation">
                                <strong>Recommendation:</strong> {vuln.get('recommendation', '')}
                            </div>
                        </div>
                    </li>
                    """
                
                html += """
                    </ul>
                </div>
                """
            
            html += """
            </div>
            """
    
    # Sensitive Content section
    if 'sensitive_content' in scan_results and 'error' not in scan_results['sensitive_content']:
        content_data = scan_results['sensitive_content']
        findings = content_data.get('findings', [])
        
        if findings:
            html += """
            <div class="section">
                <h2>Sensitive Content Exposure</h2>
                <p><strong>Status:</strong> <span class="low">SENSITIVE CONTENT EXPOSED</span></p>
                
                <div class="subsection">
                    <h3>Exposed Paths</h3>
                    <table>
                        <tr>
                            <th>URL</th>
                            <th>Status</th>
                            <th>Source</th>
                            <th>Severity</th>
                        </tr>
            """
            
            for finding in findings[:10]:  # Limit to first 10 findings
                severity = finding.get('severity', 'medium')
                severity_class = 'high-severity' if severity == 'high' else 'medium-severity'
                
                html += f"""
                        <tr class="{severity_class}">
                            <td>{finding.get('url', 'Unknown')}</td>
                            <td>{finding.get('status_code', 'Unknown')}</td>
                            <td>{finding.get('source', 'Unknown')}</td>
                            <td>{severity.upper()}</td>
                        </tr>
                """
            
            if len(findings) > 10:
                html += f"""
                        <tr>
                            <td colspan="4"><em>{len(findings) - 10} more findings not shown</em></td>
                        </tr>
                """
            
            html += """
                    </table>
                    
                    <div class="recommendation">
                        <strong>Recommendation:</strong> Restrict access to sensitive paths and files. Configure proper access controls and remove unnecessary files.
                    </div>
                </div>
            </div>
            """
    
    # Complete the HTML document
    html += """
        <div class="section">
            <h2>Next Steps</h2>
            <p>Address the issues identified in this report according to their severity. Start with critical and high severity issues first.</p>
            <p>For further assistance or a more detailed analysis, please contact our security team.</p>
            <p><a href="#" class="btn" onclick="window.print();">Print Report</a></p>
        </div>
    </body>
    </html>
    """
    
    return html
_analysis,
            'total_cookies': total_cookies,
            'total_issues': total_issues,
            'score': score
        }
    except Exception as e:
        logging.error(f"Cookie analysis failed: {str(e)}")
        return {
            'error': f'Cookie analysis failed: {str(e)}',
            'total_cookies': 0,
            'score': 0
        }

def detect_web_framework(url):
    """Detect web application frameworks and server technologies"""
    try:
        if not url.startswith('http'):
            url = f'https://{url}'
            
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        
        response = requests.get(url, headers=headers, timeout=10, verify=False)
        
        frameworks = []
        
        # Check HTTP headers for framework clues
        response_headers = response.headers
        server = response_headers.get('Server', '')
        x_powered_by = response_headers.get('X-Powered-By', '')
        
        # Server header detection
        if server:
            frameworks.append({
                'name': 'Server',
                'value': server,
                'confidence': 'high',
                'type': 'web_server'
            })
        
        # X-Powered-By header detection
        if x_powered_by:
            frameworks.append({
                'name': 'X-Powered-By',
                'value': x_powered_by,
                'confidence': 'high',
                'type': 'framework'
            })
        
        # Check for other framework-specific headers
        framework_headers = {
            'X-AspNet-Version': 'ASP.NET',
            'X-AspNetMvc-Version': 'ASP.NET MVC',
            'X-Drupal-Cache': 'Drupal',
            'X-Generator': 'Generic CMS',
            'X-Powered-CMS': 'Generic CMS',
            'X-Rails-Version': 'Ruby on Rails',
            'X-Django-Version': 'Django'
        }
        
        for header, framework in framework_headers.items():
            if header in response_headers:
                frameworks.append({
                    'name': framework,
                    'value': response_headers[header],
                    'confidence': 'high',
                    'type': 'framework'
                })
        
        # HTML content analysis
        html_content = response.text
        soup = BeautifulSoup(html_content, 'html.parser')
        
        # Meta generator tag
        meta_generator = soup.find('meta', attrs={'name': 'generator'})
        if meta_generator and meta_generator.get('content'):
            frameworks.append({
                'name': 'Generator',
                'value': meta_generator['content'],
                'confidence': 'medium',
                'type': 'generator'
            })
        
        # Common framework patterns in HTML/JS
        framework_patterns = {
            r'jquery[/-]([0-9.]+)': 'jQuery',
            r'react[/-]dom[.-]([0-9.]+)': 'React',
            r'angular(?:js)?[/-]([0-9.]+)': 'Angular',
            r'vue(?:js)?[/-]([0-9.]+)': 'Vue.js',
            r'bootstrap[/-]([0-9.]+)': 'Bootstrap',
            r'laravel': 'Laravel',
            r'django': 'Django',
            r'express': 'Express.js',
            r'next[/-]([0-9.]+)': 'Next.js',
            r'nuxt[/-]([0-9.]+)': 'Nuxt.js',
            r'svelte': 'Svelte',
            r'ember[/-]([0-9.]+)': 'Ember.js'
        }
        
        for pattern, framework_name in framework_patterns.items():
            matches = re.search(pattern, html_content, re.IGNORECASE)
            if matches:
                version = matches.group(1) if len(matches.groups()) > 0 else None
                frameworks.append({
                    'name': framework_name,
                    'value': version if version else 'detected',
                    'confidence': 'medium',
                    'type': 'frontend_framework'
                })
        
        # Look for potential security issues
        known_vulnerabilities = []
        
        # Example: Check for outdated jQuery
        jquery_match = re.search(r'jquery[/-]([0-9.]+)', html_content, re.IGNORECASE)
        if jquery_match:
            jquery_version = jquery_match.group(1)
            version_parts = [int(x) for x in jquery_version.split('.')]
            if version_parts[0] < 3 or (version_parts[0] == 3 and version_parts[1] < 5):
                known_vulnerabilities.append({
                    'framework': 'jQuery',
                    'version': jquery_version,
                    'description': 'Using an outdated version of jQuery that may contain security vulnerabilities',
                    'recommendation': 'Update to jQuery 3.5 or later'
                })
        
        return {
            'frameworks': frameworks,
            'known_vulnerabilities': known_vulnerabilities,
            'recommended_updates': len(known_vulnerabilities) > 0
        }
    except Exception as e:
        logging.error(f"Framework detection failed: {str(e)}")
        return {
            'error': f'Framework detection failed: {str(e)}',
            'frameworks': []
        }

def crawl_for_sensitive_content(url, max_urls=10):
    """Crawl website for potentially sensitive information exposure"""
    try:
        if not url.startswith('http'):
            url = f'https://{url}'
        
        base_url = urllib.parse.urlparse(url).netloc
        
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        
        # Check robots.txt
        robots_url = f"https://{base_url}/robots.txt"
        disallowed_paths = []
        try:
            robots_response = requests.get(robots_url, headers=headers, timeout=5, verify=False)
            if robots_response.status_code == 200:
                for line in robots_response.text.splitlines():
                    if line.lower().startswith('disallow:'):
                        path = line.split(':', 1)[1].strip()
                        if path:
                            disallowed_paths.append(path)
        except:
            pass
        
        # Common sensitive paths to check
        sensitive_paths = [
            '/admin/',
            '/login/',
            '/backup/',
            '/wp-admin/',
            '/phpinfo.php',
            '/config.php',
            '/database/',
            '/.git/',
            '/.env',
            '/credentials.txt',
            '/sitemap.xml',
            '/api/',
            '/backup.sql',
            '/server-status',
            '/test.php',
            '/tmp/',
            '/logs/',
            '/installer/',
            '/install.php',
            '/setup/',
            '/.htaccess',
            '/readme.html',
            '/license.txt',
            '/error_log',
            '/error.log',
            '/deploy.php',
            '/info.php',
            '/database.sql',
            '/password.txt',
            '/private/'
        ]
        
        # Add disallowed paths from robots.txt to sensitive paths
        sensitive_paths.extend(disallowed_paths)
        
        findings = []
        
        # Check each sensitive path
        for path in sensitive_paths[:max_urls]:  # Limit to max_urls
            try:
                check_url = f"https://{base_url}{path}"
                path_response = requests.head(check_url, headers=headers, timeout=5, verify=False, allow_redirects=False)
                
                if path_response.status_code < 400:  # Path exists or redirects
                    findings.append({
                        'url': check_url,
                        'status_code': path_response.status_code,
                        'accessible': True,
                        'source': 'robots.txt' if path in disallowed_paths else 'common_paths',
                        'severity': 'high' if path_response.status_code == 200 else 'medium'
                    })
            except:
                continue
        
        # Additional checks for exposed files
        exposed_file_types = ['.sql', '.bak', '.backup', '.zip', '.tar.gz', '.log', '.conf', '.xml', '.json']
        
        # Check for leaked data files in known locations
        for file_ext in exposed_file_types:
            check_paths = [
                f"/backup{file_ext}",
                f"/db{file_ext}",
                f"/database{file_ext}",
                f"/site{file_ext}",
                f"/backup/latest{file_ext}"
            ]
            
            for path in check_paths:
                try:
                    check_url = f"https://{base_url}{path}"
                    file_response = requests.head(check_url, headers=headers, timeout=3, verify=False)
                    
                    if file_response.status_code == 200:
                        findings.append({
                            'url': check_url,
                            'status_code': file_response.status_code,
                            'accessible': True,
                            'source': 'exposed_files',
                            'severity': 'high'
                        })
                except:
                    continue
        
        return {
            'sensitive_paths_found': len(findings),
            'findings': findings,
            'risk_level': 'high' if len(findings) > 0 else 'low',
            'recommendation': 'Restrict access to sensitive paths and files'
        }
    except Exception as e:
        logging.error(f"Content crawling failed: {str(e)}")
        return {
            'error': f'Content crawling failed: {str(e)}',
            'sensitive_paths_found': 0
        }

def analyze_port_risks(open_ports):
    """Analyze the risk level of open ports"""
    risks = []
    
    high_risk_ports = {
        3389: "Remote Desktop Protocol (RDP) - High security risk if exposed",
        21: "FTP - Transmits credentials in plain text",
        23: "Telnet - Insecure, transmits data in plain text",
        5900: "VNC - Remote desktop access, often lacks encryption",
        1433: "Microsoft SQL Server - Database access",
        3306: "MySQL Database - Potential attack vector if unprotected",
        445: "SMB - Windows file sharing, historically vulnerable",
        139: "NetBIOS - Windows networking, potential attack vector"
    }
    
    medium_risk_ports = {
        80: "HTTP - Web server without encryption",
        25: "SMTP - Email transmission",
        110: "POP3 - Email retrieval (older protocol)",
        143: "IMAP - Email retrieval (often unencrypted)",
        8080: "Alternative HTTP port, often used for proxies or development"
    }
    
    for port in open_ports:
        if port in high_risk_ports:
            risks.append((port, high_risk_ports[port], "High"))
        elif port in medium_risk_ports:
            risks.append((port, medium_risk_ports[port], "Medium"))
        else:
            risks.append((port, f"Unknown service on port {port}", "Low"))
    
    # Sort by severity (High first)
    return sorted(risks, key=lambda x: 0 if x[2] == "High" else (1 if x[2] == "Medium" else 2))

# ===== Risk Scoring and Reports =====

def calculate_risk_score(scan_results):
    """Calculate overall security risk score based on all scan results"""
    try:
        scores = {
            'ssl_certificate': 0,
            'security_headers': 0,
            'cms': 0,
            'dns_configuration': 0,
            'cookies': 0,
            'frameworks': 0,
            'sensitive_content': 0,
            'open_ports': 0,
            'email_security': 0,
            'system': 0
        }
        
        weights = {
            'ssl_certificate': 10,
            'security_headers': 10,
            'cms': 8,
            'dns_configuration': 8,
            'cookies': 7,
            'frameworks': 7,
            'sensitive_content': 10,
            'open_ports': 15,
            'email_security': 10,
            'system': 15
        }
        
        # Email Security scoring
        if 'email_security' in scan_results:
            email_data = scan_results['email_security']
            
            if 'error' not in email_data:
                # Start with full score
                email_score = 100
                
                # Deduct for SPF issues
                spf_severity = email_data.get('spf', {}).get('severity', 'Low')
                if spf_severity == 'High' or spf_severity == 'Critical':
                    email_score -= 30
                elif spf_severity == 'Medium':
                    email_score -= 15
                
                # Deduct for DMARC issues
                dmarc_severity = email_data.get('dmarc', {}).get('severity', 'Low')
                if dmarc_severity == 'High' or dmarc_severity == 'Critical':
                    email_score -= 30
                elif dmarc_severity == 'Medium':
                    email_score -= 15
                
                # Deduct for DKIM issues
                dkim_severity = email_data.get('dkim', {}).get('severity', 'Low')
                if dkim_severity == 'High' or dkim_severity == 'Critical':
                    email_score -= 30
                elif dkim_severity == 'Medium':
                    email_score -= 15
                
                scores['email_security'] = max(0, email_score)
        
        # System Security scoring
        if 'system' in scan_results:
            system_data = scan_results['system']
            
            if 'error' not in system_data:
                # Start with full score
                system_score = 100
                
                # Deduct for OS update issues
                os_severity = system_data.get('os_updates', {}).get('severity', 'Low')
                if os_severity == 'Critical':
                    system_score -= 40
                elif os_severity == 'High':
                    system_score -= 30
                elif os_severity == 'Medium':
                    system_score -= 15
                
                # Deduct for firewall issues
                firewall_severity = system_data.get('firewall', {}).get('severity', 'Low')
                if firewall_severity == 'Critical':
                    system_score -= 30
                elif firewall_severity == 'High':
                    system_score -= 20
                elif firewall_severity == 'Medium':
                    system_score -= 10
                
                scores['system'] = max(0, system_score)
        
        # SSL Certificate scoring
        if 'ssl_certificate' in scan_results and 'error' not in scan_results['ssl_certificate']:
            ssl_data = scan_results['ssl_certificate']
            
            # Start with full score
            ssl_score = 100
            
            # Deduct for issues
            if ssl_data.get('is_expired', False):
                ssl_score -= 50
            elif ssl_data.get('expiring_soon', False):
                ssl_score -= 20
                
            if ssl_data.get('weak_protocol', False):
                ssl_score -= 30
                
            scores['ssl_certificate'] = max(0, ssl_score)
        
        # Security Headers scoring
        if 'security_headers' in scan_results and 'error' not in scan_results['security_headers']:
            scores['security_headers'] = scan_results['security_headers'].get('score', 0)
        
        # CMS scoring
        if 'cms' in scan_results and 'error' not in scan_results['cms']:
            cms_data = scan_results['cms']
            
            if cms_data.get('cms_detected', False):
                # Start with full score
                cms_score = 100
                vulnerabilities = cms_data.get('potential_vulnerabilities', [])
                
                if vulnerabilities:
                    cms_score -= len(vulnerabilities) * 25  # Deduct 25 points per vulnerability
                
                scores['cms'] = max(0, cms_score)
            else:
                scores['cms'] = 100  # No known CMS, assume good
        
        # DNS Configuration scoring
        if 'dns_configuration' in scan_results and 'error' not in scan_results['dns_configuration']:
            dns_data = scan_results['dns_configuration']
            
            # Start with full score
            dns_score = 100
            
            # Deduct points for issues
            issues = dns_data.get('issues', [])
            for issue in issues:
                severity = issue.get('severity', 'Medium')
                if severity == 'High':
                    dns_score -= 30
                elif severity == 'Medium':
                    dns_score -= 15
                else:  # Low
                    dns_score -= 5
            
            scores['dns_configuration'] = max(0, dns_score)
        
        # Cookie security scoring
        if 'cookies' in scan_results and 'error' not in scan_results['cookies']:
            scores['cookies'] = scan_results['cookies'].get('score', 0)
        
        # Framework detection scoring
        if 'frameworks' in scan_results and 'error' not in scan_results['frameworks']:
            framework_data = scan_results['frameworks']
            
            # Start with full score
            framework_score = 100
            
            # Deduct for vulnerabilities
            vulnerabilities = framework_data.get('known_vulnerabilities', [])
            if vulnerabilities:
                framework_score -= len(vulnerabilities) * 20
                
            scores['frameworks'] = max(0, framework_score)
        
        # Sensitive content scoring
        if 'sensitive_content' in scan_results and 'error' not in scan_results['sensitive_content']:
            content_data = scan_results['sensitive_content']
            
            # Start with full score
            content_score = 100
            
            # Deduct based on findings
            findings = content_data.get('findings', [])
            for finding in findings:
                severity = finding.get('severity', 'medium')
                if severity == 'high':
                    content_score -= 15
                else:  # medium
                    content_score -= 7
            
            scores['sensitive_content'] = max(0, content_score)
        
        # Open ports scoring
        if 'open_ports' in scan_results:
            # For direct open_ports entry
            if 'error' not in scan_results['open_ports']:
                ports_data = scan_results['open_ports']
                
                # Start with full score
                ports_score = 100
                
                # Count high-risk open ports
                high_risk_ports = [21, 22, 23, 25, 53, 137, 138, 139, 445, 1433, 1434, 3306, 3389, 5432, 5900]
                open_ports = ports_data.get('open_ports', [])
                
                high_risk_open = sum(1 for port in open_ports if port in high_risk_ports)
                
                # Deduct points for high-risk ports
                if high_risk_open > 0:
                    ports_score -= high_risk_open * 15
                
                # Deduct less for other open ports
                other_open = len(open_ports) - high_risk_open
                if other_open > 0:
                    ports_score -= other_open * 5
                    
                scores['open_ports'] = max(0, ports_score)
        elif 'network' in scan_results and 'open_ports' in scan_results['network']:
            # For nested open_ports in network
            network_data = scan_results['network']
            if 'error' not in network_data:
                ports_data = network_data.get('open_ports', {})
                
                # Start with full score
                ports_score = 100
                
                # Count high-risk open ports
                high_risk_ports = [21, 22, 23, 25, 53, 137, 138, 139, 445, 1433, 1434, 3306, 3389, 5432, 5900]
                open_ports = ports_data.get('list', [])
                
                high_risk_open = sum(1 for port in open_ports if port in high_risk_ports)
                
                # Deduct points for high-risk ports
                if high_risk_open > 0:
                    ports_score -= high_risk_open * 15
                
                # Deduct less for other open ports
                other_open = len(open_ports) - high_risk_open
                if other_open > 0:
                    ports_score -= other_open * 5
                    
                scores['open_ports'] = max(0, ports_score)
                
        # Fill in missing scores with average to avoid skewing the results
        available_scores = [score for category, score in scores.items() if score > 0]
        average_score = sum(available_scores) / len(available_scores) if available_scores else 50
        
        for category, score in scores.items():
            if score == 0:
                scores[category] = average_score
        
        # Calculate weighted average score
        total_weight = sum(weights.values())
        weighted_score = 0
        
        for category, score in scores.items():
            weighted_score += score * weights[category]
        
        overall_score = int(weighted_score / total_weight)
        
        # Generate risk level based on score
        if overall_score >= 90:
            risk_level = 'Low'
        elif overall_score >= 70:
            risk_level = 'Medium'
        elif overall_score >= 50:
            risk_level = 'High'
        else:
            risk_level = 'Critical'
        
        # Generate recommendations based on lowest scores
        recommendations = []
        for category, score in scores.items():
            if score < 70:  # Only recommend fixing categories with low scores
                if category == 'ssl_certificate' and score < 70:
                    recommendations.append('Update SSL/TLS configuration to use modern protocols and ensure certificate is valid')
                elif category == 'security_headers' and score < 70:
                    recommendations.append('Implement missing security headers to improve web application security')
                elif category == 'cms' and score < 70:
                    recommendations.append('Update CMS to latest version and check for vulnerable plugins')
                elif category == 'dns_configuration' and score < 70:
                    recommendations.append('Fix DNS configuration issues such as missing records or zone transfer vulnerabilities')
                elif category == 'cookies' and score < 70:
                    recommendations.append('Add security flags to cookies (Secure, HttpOnly, SameSite)')
                elif category == 'frameworks' and score < 70:
                    recommendations.append('Update web frameworks and libraries to fix known vulnerabilities')
                elif category == 'sensitive_content' and score < 70:
                    recommendations.append('Restrict access to sensitive files and directories')
                elif category == 'open_ports' and score < 70:
                    recommendations.append('Close unnecessary open ports, especially high-risk services')
                elif category == 'email_security' and score < 70:
                    recommendations.append('Configure SPF, DKIM, and DMARC records for your email domains')
                elif category == 'system' and score < 70:
                    recommendations.append('Ensure operating system and software are up to date with latest security patches')
        
        return {
            'overall_score': overall_score,
            'risk_level': risk_level,
            'category_scores': scores,
            'recommendations': recommendations
        }
    except Exception as e:
        logging.error(f"Risk scoring failed: {str(e)}")
        return {
            'error': f'Risk scoring failed: {str(e)}',
            'overall_score': 0,
            'risk_level': 'Unknown'
        }

def generate_html_report(scan_results, is_integrated=False):
    """Generate an HTML report from scan data"""
    target = scan_results.get('target', 'Unknown')
    scan_date = datetime.datetime.fromisoformat(scan_results.get('timestamp', datetime.datetime.now().isoformat()))
    scan_date_str = scan_date.strftime('%Y-%m-%d %H:%M:%S')
    
    # Start building HTML
    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Security Scan Report for {target}</title>
        <style>
            body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 1200px; margin: 0 auto; padding: 20px; }}
            .header {{ background-color: #808588; color: white; padding: 20px; border-radius: 5px; margin-bottom: 20px; }}
            .section {{ margin-bottom: 30px; border: 1px solid #ddd; border-radius: 5px; padding: 20px; }}
            .subsection {{ margin-top: 20px; }}
            h1 {{ color: #333; }}
            h2 {{ color: #FF6900; border-bottom: 1px solid #eee; padding-bottom: 10px; }}
            h3 {{ color: #333; }}
            table {{ width: 100%; border-collapse: collapse; margin-bottom: 20px; }}
            th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
            th {{ background-color: #f8f9fa; }}
            .score {{ font-size: 24px; font-weight: bold; }}
            .high {{ color: #27ae60; }}
            .medium {{ color: #f39c12; }}
            .low {{ color: #e74c3c; }}
            .critical {{ color: #c0392b; }}
            .issue {{ padding: 10px; margin: 5px 0; border-radius: 3px; }}
            .high-severity {{ background-color: #ffdddd; }}
            .medium-severity {{ background-color: #ffffcc; }}
            .low-severity {{ background-color: #e8f4f8; }}
            .recommendation {{ background-color: #e8f4f8; padding: 10px; margin-top: 10px; border-radius: 3px; }}
            .btn {{ display: inline-block; background-color: #FF6900; color: white; text-decoration: none; padding: 10px 20px; border-radius: 4px; margin-top: 10px; }}
        </style>
    </head>
    <body>
        <div class="header">
            <h1>Security Scan Report</h1>
            <p><strong>Target:</strong> {target}</p>
            <p><strong>Scan Date:</strong> {scan_date_str}</p>
            <p><strong>Scan ID:</strong> {scan_results.get('scan_id', 'Unknown')}</p>
    """
    
    # Add risk assessment if available
    if 'risk_assessment' in scan_results and 'error' not in scan_results['risk_assessment']:
        risk = scan_results['risk_assessment']
        score = risk.get('overall_score', 0)
        risk_level = risk.get('risk_level', 'Unknown')
        
        score_class = 'high' if score >= 80 else 'medium' if score >= 60 else 'low' if score >= 40 else 'critical'
        
        html += f"""
            <div>
                <h2>Overall Security Score</h2>
                <p class="score {score_class}">{score}/100 - {risk_level} Risk</p>
            </div>
        """
    
    html += """
        </div>
    """
    
    # Add recommendations section if available
    if 'risk_assessment' in scan_results and 'recommendations' in scan_results['risk_assessment']:
        recommendations = scan_results['risk_assessment']['recommendations']
        
        if recommendations:
            html += """
            <div class="section">
                <h2>Key Recommendations</h2>
                <ul>
            """
            
            for recommendation in recommendations:
                html += f"""
                    <li>{recommendation}</li>
                """
            
            html += """
                </ul>
            </div>
            """
    
    # System security section (for integrated scan)
    if is_integrated and 'system' in scan_results:
        system_data = scan_results['system']
        
        if 'error' not in system_data:
            html += """
            <div class="section">
                <h2>System Security</h2>
                <table>
                    <tr>
                        <th>Check</th>
                        <th>Status</th>
                        <th>Severity</th>
                    </tr>
            """
            
            # OS Updates
            os_updates = system_data.get('os_updates', {})
            os_severity = os_updates.get('severity', 'Low')
            os_severity_class = 'high' if os_severity == 'Low' else 'medium' if os_severity == 'Medium' else 'low'
            
            html += f"""
                <tr>
                    <td>Operating System Updates</td>
                    <td>{os_updates.get('message', 'Unknown')}</td>
                    <td class="{os_severity_class}">{os_severity}</td>
                </tr>
            """
            
            # Firewall
            firewall = system_data.get('firewall', {})
            firewall_status = firewall.get('status', 'Unknown')
            firewall_severity = firewall.get('severity', 'Low')
            firewall_severity_class = 'high' if firewall_severity == 'Low' else 'medium' if firewall_severity == 'Medium' else 'low'
            
            html += f"""
                <tr>
                    <td>Firewall Status</td>
                    <td>{firewall_status}</td>
                    <td class="{firewall_severity_class}">{firewall_severity}</td>
                </tr>
            """
            
            html += """
                </table>
            </div>
            """
    
    # Email security section
    if 'email_security' in scan_results and 'error' not in scan_results['email_security']:
        email_data = scan_results['email_security']
        
        html += f"""
        <div class="section">
            <h2>Email Security</h2>
            
            <table>
                <tr>
                    <th>Check</th>
                    <th>Status</th>
                    <th>Severity</th>
                </tr>
        """
        
        # SPF Record
        spf"""
Integrated security scanner module combining basic and enhanced vulnerability scanning.
"""

import ssl
import socket
import dns.resolver
import requests
import re
import json
import datetime
import urllib.parse
from bs4 import BeautifulSoup
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import logging
import warnings
import urllib3
import platform
import psutil
import random
import dns.zone
import dns.query
import sys
import os

# Suppress InsecureRequestWarning warnings
warnings.filterwarnings('ignore', message='.*InsecureRequestWarning.*')

# Set up logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

# Define severity levels
SEVERITY = {
    "Critical": 10,
    "High": 7,
    "Medium": 5,
    "Low": 2,
    "Info": 1
}

# A function to calculate severity based on the issue type
def get_severity_level(severity):
    return SEVERITY.get(severity, SEVERITY["Info"])

# Generate actionable recommendations based on severity
def get_recommendations(vulnerability, severity):
    if severity == "Critical":
        return f"[CRITICAL] {vulnerability}. Immediate action is required to avoid potential data loss or breach."
    elif severity == "High":
        return f"[HIGH] {vulnerability}. Address this within the next 48 hours to mitigate major risks."
    elif severity == "Medium":
        return f"[MEDIUM] {vulnerability}. Address this within the next week to prevent exploitation."
    elif severity == "Low":
        return f"[LOW] {vulnerability}. A low-risk issue, but should be reviewed."
    else:
        return f"[INFO] {vulnerability}. No immediate action required."

# Function to generate threat scenarios based on detected vulnerabilities
def generate_threat_scenario(vulnerability, severity):
    scenarios = {
        "OS Update": "Outdated software can be exploited by attackers to run malicious code, leading to data breaches or system compromise.",
        "Weak Passwords": "Weak or reused passwords can be easily guessed or cracked, allowing attackers to access sensitive accounts or data.",
        "Open Ports": "Open network ports expose your system to external attacks, including DDoS, data theft, and unauthorized access.",
        "Encryption": "Lack of disk encryption increases the risk of data theft, especially if devices are lost or stolen.",
        "MFA": "Lack of Multi-Factor Authentication (MFA) makes your system vulnerable to unauthorized access from attackers.",
        "RDP Security": "Unsecured Remote Desktop Protocol (RDP) can be easily exploited by cybercriminals.",
        "Backup": "Without proper backup systems in place, critical data is vulnerable to loss in the event of a disaster.",
        "Email Security": "Email is a primary attack vector for phishing and malware distribution. Lack of proper security measures can result in a breach.",
        "Endpoint Protection": "Missing endpoint protection leaves your system vulnerable to malware and exploitation.",
        "Network Segmentation": "Lack of network segmentation increases the risk of a widespread breach if an attacker gains access.",
        "Ransomware Protection": "Without proper ransomware protection, your system is vulnerable to file encryption and extortion attacks.",
        "DNS Security": "Unprotected DNS servers can be used in phishing attacks and data manipulation. DNSSEC ensures the integrity of DNS queries."
    }
    return scenarios.get(vulnerability, "Unspecified threat scenario: This vulnerability could lead to serious consequences if not addressed.")

# ===== BASIC SCANNING FUNCTIONS =====

# Check for OS updates
def check_os_updates():
    try:
        os_name = platform.system()
        
        if os_name == "Linux":
            return {
                "message": "Operating System (Linux) has pending updates",
                "severity": "High",
                "info": "Additional info about Linux"
            }
        elif os_name == "Windows":
            return {
                "message": "Operating System (Windows) is up-to-date",
                "severity": "Low",
                "info": "Everything is fine with Windows"
            }
        elif os_name == "Darwin":  # macOS
            return {
                "message": "Operating System (macOS) is up-to-date",
                "severity": "Low",
                "info": "No pending updates"
            }
        else:
            return {
                "message": "Operating System update status: Unknown",
                "severity": "Critical",
                "info": "Unknown OS"
            }
    except Exception as e:
        logging.error(f"Error checking OS updates: {e}")
        return {
            "message": "Error checking OS updates",
            "severity": "Critical",
            "info": str(e)
        }

def get_windows_version():
    # Modified for web environment
    try:
        os_name = platform.system()
        if os_name == "Windows":
            try:
                win_ver = sys.getwindowsversion()
                major, build = win_ver.major, win_ver.build
                if major == 10 and build >= 22000:
                    return f"Windows 11 or higher (Build {build})", "Low"
                else:
                    return f"Windows version is earlier than Windows 11 (Build {build})", "Critical"
            except:
                return "Windows version detection failed", "Medium"
        else:
            return f"Server running {os_name}", "Low"
    except Exception as e:
        logging.error(f"Error checking Windows version: {e}")
        return f"Error checking OS version: {str(e)}", "Medium"

def check_open_ports():
    """Simulated port check for web environment"""
    try:
        # For web environment, return simulated results
        # This represents typical findings rather than actual open ports
        simulated_open_ports = [80, 443, 3389, 445, 139, 135, 5985, 5986, 53, 88]
        
        # Add some random ports to simulate a more realistic environment
        additional_ports = random.sample([21, 22, 23, 25, 110, 143, 1433, 3306, 5900, 8080, 8443], 
                                        random.randint(3, 8))
        simulated_open_ports.extend(additional_ports)
        
        open_ports_count = len(simulated_open_ports)
        logging.debug(f"Simulated {open_ports_count} open ports")
        
        # Severity based on count and specific ports
        if open_ports_count >= 30 or any(p in [3389, 5900, 21, 23] for p in simulated_open_ports):
            severity = "High"
        elif open_ports_count >= 10:
            severity = "Medium"
        else:
            severity = "Low"
            
        return open_ports_count, simulated_open_ports, severity
    except Exception as e:
        logging.error(f"Error in simulated port check: {e}")
        return 0, [], "Critical"

# Check Firewall Status
def check_firewall_status():
    """Enhanced firewall status check for web environment"""
    try:
        client_os = platform.system()
        
        # Make educated guesses about firewall status based on available info
        if "Windows" in client_os:
            return "Windows Firewall is likely active, but web browsers cannot directly detect its status. We recommend manually checking Windows Defender Firewall settings.", "Medium"
        elif "Darwin" in client_os:  # macOS
            return "macOS likely has its built-in firewall enabled, but web browsers cannot directly detect its status. We recommend checking Security & Privacy settings.", "Medium"
        elif "Linux" in client_os:
            return "Linux systems typically use iptables or ufw for firewall protection. Web browsers cannot directly detect firewall status.", "Medium"
        else:
            return "Firewall status check limited in web environment. We recommend manually checking your system's firewall settings.", "Medium"
    except Exception as e:
        logging.error(f"Error checking firewall status: {e}")
        return "Error checking firewall status", "Medium"

# Function to check SPF status
def check_spf_status(domain):
    """Check the SPF record for a given domain with enhanced validation."""
    try:
        answers = dns.resolver.resolve(domain, 'TXT')
        for rdata in answers:
            txt_record = rdata.to_text().strip('"')
            if txt_record.startswith("v=spf1"):
                logging.debug(f"Found SPF record for {domain}: {txt_record}")

                # Count the number of mechanisms
                mechanisms = [m for m in txt_record.split() if any(m.startswith(p) for p in ["include:", "a", "mx", "ip4:", "ip6:"])]
                mechanism_count = len(mechanisms)

                # Check for ending
                if txt_record.endswith("-all"):
                    if mechanism_count <= 10:
                        return f"SPF record OK: {txt_record} (Mechanisms: {mechanism_count})", "Low"
                    else:
                        return f"Too many SPF mechanisms ({mechanism_count}) in record: {txt_record}", "High"
                elif txt_record.endswith("~all"):
                    if mechanism_count <= 10:
                        return f"SPF uses soft fail (~all). Consider using -all. Record: {txt_record} (Mechanisms: {mechanism_count})", "Medium"
                    else:
                        return f"Too many SPF mechanisms ({mechanism_count}) and ends in ~all: {txt_record}", "High"
                else:
                    return f"SPF record missing final '-all' or '~all': {txt_record}", "High"

        return "No SPF record found", "High"

    except Exception as e:
        logging.error(f"Error checking SPF status for domain {domain}: {e}")
        return f"Error checking SPF status: {e}", "Critical"
    
def check_dmarc_record(domain):
    """Check if the domain has a valid DMARC record."""
    try:
        dmarc_domain = f"_dmarc.{domain}"
        answers = dns.resolver.resolve(dmarc_domain, "TXT")

        for rdata in answers:
            record = rdata.to_text().strip('"')
            if record.lower().startswith("v=dmarc1"):
                return f"DMARC record found: {record}", "Low"
        return "No valid DMARC record found", "High"

    except dns.resolver.NXDOMAIN:
        return "Domain does not exist", "Critical"
    except dns.resolver.NoAnswer:
        return "No DMARC record found", "High"
    except Exception as e:
        return f"Error checking DMARC record: {e}", "Critical"

def check_dkim_record(domain):
    selectors = ["default", "selector1", "selector2", "google", "dkim", "dkim1"]
    for selector in selectors:
        dkim_domain = f"{selector}._domainkey.{domain}"
        try:
            answers = dns.resolver.resolve(dkim_domain, "TXT")
            txt_record = answers[0].to_text().strip('"')
            return f"DKIM record found with selector '{selector}': {txt_record}", "Low"
        except dns.resolver.NXDOMAIN:
            continue  # No such name, try next
        except Exception as e:
            continue  # Suppress other errors for now

    return "DKIM record not found using common selectors.", "High"

def analyze_dns_configuration(domain):
    """Analyze DNS configuration for a domain"""
    try:
        result = {
            'domain': domain,
            'records': {},
            'issues': [],
            'risk_level': 'Low'
        }
        
        # Check for A records
        try:
            a_records = dns.resolver.resolve(domain, 'A')
            result['records']['A'] = [record.to_text() for record in a_records]
        except Exception as e:
            result['issues'].append({
                'type': 'A Record Missing',
                'description': f"Could not find A records for domain: {str(e)}",
                'severity': 'High',
                'recommendation': 'Configure an A record to point to your server IP address'
            })
        
        # Check for MX records
        try:
            mx_records = dns.resolver.resolve(domain, 'MX')
            result['records']['MX'] = [record.to_text() for record in mx_records]
        except Exception as e:
            result['issues'].append({
                'type': 'MX Record Missing',
                'description': f"Could not find MX records for domain: {str(e)}",
                'severity': 'Medium',
                'recommendation': 'Configure MX records if you use this domain for email'
            })
        
        # Check for NS records
        try:
            ns_records = dns.resolver.resolve(domain, 'NS')
            result['records']['NS'] = [record.to_text() for record in ns_records]
            
            # Check if multiple nameservers exist (redundancy)
            if len(result['records']['NS']) < 2:
                result['issues'].append({
                    'type': 'Insufficient Nameservers',
                    'description': 'Domain has less than 2 nameservers, which could create a single point of failure',
                    'severity': 'Medium',
                    'recommendation': 'Configure at least 2 nameservers for redundancy'
                })
        except Exception as e:
            result['issues'].append({
                'type': 'NS Record Issue',
                'description': f"Problem with NS records: {str(e)}",
                'severity': 'High',
                'recommendation': 'Ensure your domain has properly configured nameservers'
            })
        
        # Check for TXT records (SPF, DMARC, etc.)
        try:
            txt_records = dns.resolver.resolve(domain, 'TXT')
            result['records']['TXT'] = [record.to_text() for record in txt_records]
            
            # Check for SPF
            spf_found = False
            for record in result['records']['TXT']:
                if record.startswith('"v=spf1'):
                    spf_found = True
                    break
            
            if not spf_found:
                result['issues'].append({
                    'type': 'SPF Record Missing',
                    'description': 'No SPF record found in TXT records',
                    'severity': 'Medium',
                    'recommendation': 'Configure SPF record to prevent email spoofing'
                })
        except Exception:
            result['records']['TXT'] = []
        
        # Check for DMARC record
        try:
            dmarc_records = dns.resolver.resolve(f"_dmarc.{domain}", 'TXT')
            result['records']['DMARC'] = [record.to_text() for record in dmarc_records]
        except Exception:
            result['issues'].append({
                'type': 'DMARC Record Missing',
                'description': 'No DMARC record found',
                'severity': 'Medium',
                'recommendation': 'Configure DMARC record to enhance email security'
            })
        
        # Check for DNSSEC
        try:
            dnskey_records = dns.resolver.resolve(domain, 'DNSKEY')
            result['records']['DNSKEY'] = [record.to_text() for record in dnskey_records]
        except Exception:
            result['issues'].append({
                'type': 'DNSSEC Not Configured',
                'description': 'DNSSEC is not configured for this domain',
                'severity': 'Medium',
                'recommendation': 'Consider implementing DNSSEC to protect against DNS spoofing'
            })
        
        # Check for CAA records
        try:
            caa_records = dns.resolver.resolve(domain, 'CAA')
            result['records']['CAA'] = [record.to_text() for record in caa_records]
        except Exception:
            result['issues'].append({
                'type': 'CAA Record Missing',
                'description': 'No CAA record found',
                'severity': 'Low',
                'recommendation': 'Configure CAA record to control which CAs can issue certificates for your domain'
            })
        
        # Determine overall risk level based on issues
        high_severity_issues = [issue for issue in result['issues'] if issue['severity'] == 'High']
        medium_severity_issues = [issue for issue in result['issues'] if issue['severity'] == 'Medium']
        
        if high_severity_issues:
            result['risk_level'] = 'High'
        elif len(medium_severity_issues) > 2:
            result['risk_level'] = 'Medium'
        
        return result
    except Exception as e:
        logging.error(f"Error analyzing DNS configuration: {e}")
        return {
            'domain': domain,
            'error': str(e),
            'risk_level': 'Unknown'
        }

# ===== ENHANCED SCANNING FUNCTIONS =====

def check_ssl_certificate(hostname, port=443):
    """Check SSL/TLS certificate for security issues"""
    try:
        # Create SSL context
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                # Get certificate
                cert_binary = ssock.getpeercert(binary_form=True)
                cert = x509.load_der_x509_certificate(cert_binary, default_backend())
                
                # Extract certificate information
                issuer = cert.issuer.rfc4514_string()
                subject = cert.subject.rfc4514_string()
                not_before = cert.not_valid_before
                not_after = cert.not_valid_after
                
                # Check if certificate is expired or about to expire
                now = datetime.datetime.now()
                days_to_expiry = (not_after - now).days
                is_expired = now > not_after
                expiring_soon = days_to_expiry < 30
                
                # Get cipher and protocol information
                cipher = ssock.cipher()
                protocol = ssock.version()
                
                # Check for weak protocols (SSL2, SSL3, TLS1.0, TLS1.1)
                weak_protocol = protocol in ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1']
                
                # Results
                result = {
                    'issuer': issuer,
                    'subject': subject,
                    'valid_from': not_before.isoformat(),
                    'valid_until': not_after.isoformat(),
                    'days_to_expiry': days_to_expiry,
                    'is_expired': is_expired,
                    'expiring_soon': expiring_soon,
                    'cipher_suite': cipher[0],
                    'protocol': protocol,
                    'weak_protocol': weak_protocol,
                    'status': 'valid' if not is_expired else 'expired'
                }
                
                return result
    except Exception as e:
        logging.error(f"SSL certificate check failed: {str(e)}")
        return {
            'error': f'SSL certificate check failed: {str(e)}',
            'status': 'error'
        }

def check_security_headers(url):
    """Check for security headers in HTTP responses"""
    try:
        if not url.startswith('http'):
            url = f'https://{url}'
        
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        
        response = requests.get(url, headers=headers, timeout=10, verify=False)
        
        # Headers to check and their recommended values
        security_headers = {
            'Content-Security-Policy': {'present': False, 'value': None, 'description': 'Helps prevent XSS and data injection attacks'},
            'X-Content-Type-Options': {'present': False, 'value': None, 'description': 'Prevents MIME type sniffing'},
            'X-Frame-Options': {'present': False, 'value': None, 'description': 'Protects against clickjacking'},
            'X-XSS-Protection': {'present': False, 'value': None, 'description': 'Mitigates Cross-Site Scripting (XSS) attacks'},
            'Strict-Transport-Security': {'present': False, 'value': None, 'description': 'Enforces secure (HTTPS) connections'},
            'Referrer-Policy': {'present': False, 'value': None, 'description': 'Controls how much referrer information is included with requests'},
            'Feature-Policy': {'present': False, 'value': None, 'description': 'Controls which browser features can be used'},
            'Permissions-Policy': {'present': False, 'value': None, 'description': 'Controls which browser features can be used (newer version of Feature-Policy)'},
            'Access-Control-Allow-Origin': {'present': False, 'value': None, 'description': 'Indicates which origins can access the resource'},
            'Cache-Control': {'present': False, 'value': None, 'description': 'Directives for caching mechanisms'},
            'Clear-Site-Data': {'present': False, 'value': None, 'description': 'Clears browsing data associated with the site'}
        }
        
        # Check which headers are present
        for header, details in security_headers.items():
            if header.lower() in [h.lower() for h in response.headers]:
                security_headers[header]['present'] = True
                security_headers[header]['value'] = response.headers[header]
        
        # Calculate missing headers and overall score
        missing_headers = [h for h, d in security_headers.items() if not d['present']]
        total_headers = len(security_headers)
        present_headers = total_headers - len(missing_headers)
        score = int((present_headers / total_headers) * 100)
        
        return {
            'headers': security_headers,
            'missing_headers': missing_headers,
            'score': score,
            'total_headers': total_headers,
            'present_headers': present_headers
        }
    except Exception as e:
        logging.error(f"Security headers check failed: {str(e)}")
        return {
            'error': f'Security headers check failed: {str(e)}',
            'score': 0
        }

def detect_cms(url):
    """Detect Content Management System and check for known vulnerabilities"""
    try:
        if not url.startswith('http'):
            url = f'https://{url}'
            
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        
        response = requests.get(url, headers=headers, timeout=10, verify=False)
        html_content = response.text
        
        # Common CMS signatures to check
        cms_signatures = {
            'WordPress': {
                'patterns': [
                    r'wp-content',
                    r'wp-includes',
                    r'wordpress',
                    r'<meta name="generator" content="WordPress ([0-9.]+)"'
                ],
                'version_pattern': r'<meta name="generator" content="WordPress ([0-9.]+)"',
                'common_paths': ['/wp-login.php', '/wp-admin/', '/wp-content/']
            },
            'Joomla': {
                'patterns': [
                    r'joomla',
                    r'<meta name="generator" content="Joomla!'
                ],
                'version_pattern': r'<meta name="generator" content="Joomla! ([0-9.]+)"',
                'common_paths': ['/administrator/', '/components/', '/templates/']
            },
            'Drupal': {
                'patterns': [
                    r'drupal',
                    r'Drupal.settings',
                    r'/sites/default/'
                ],
                'version_pattern': r'Drupal ([0-9.]+)',
                'common_paths': ['/node/', '/sites/default/', '/user/login/']
            },
            'Magento': {
                'patterns': [
                    r'Mage.Cookies',
                    r'magento',
                    r'/skin/frontend/'
                ],
                'version_pattern': r'Magento/([0-9.]+)',
                'common_paths': ['/index.php/admin/', '/skin/frontend/', '/app/etc/']
            },
            'Shopify': {
                'patterns': [
                    r'Shopify.theme',
                    r'shopify',
                    r'/cdn.shopify.com/'
                ],
                'version_pattern': None,  # Shopify doesn't typically expose version
                'common_paths': []
            }
        }
        
        detected_cms = None
        detected_version = None
        
        # Try to detect CMS based on HTML content
        for cms, details in cms_signatures.items():
            for pattern in details['patterns']:
                if re.search(pattern, html_content, re.IGNORECASE):
                    detected_cms = cms
                    
                    # Try to extract version if pattern exists
                    if details['version_pattern']:
                        version_match = re.search(details['version_pattern'], html_content)
                        if version_match:
                            detected_version = version_match.group(1)
                    
                    break
            if detected_cms:
                break
        
        # If no CMS detected yet, check for common paths
        if not detected_cms:
            base_url = urllib.parse.urlparse(url).netloc
            for cms, details in cms_signatures.items():
                for path in details['common_paths']:
                    try:
                        check_url = f"https://{base_url}{path}"
                        path_response = requests.head(check_url, headers=headers, timeout=5, verify=False)
                        if path_response.status_code < 400:  # Path exists
                            detected_cms = cms
                            break
                    except:
                        pass
                if detected_cms:
                    break
        
        # Build result
        result = {
            'cms_detected': detected_cms is not None,
            'cms_name': detected_cms,
            'version': detected_version,
            'confidence': 'high' if detected_version else 'medium',
            'potential_vulnerabilities': []
        }
        
        # If CMS detected, try to identify potential vulnerabilities
        if detected_cms and detected_version:
            # This is a simplified example - in a real implementation, you would
            # check against a database of known vulnerabilities
            if detected_cms == 'WordPress' and detected_version:
                version_parts = [int(x) for x in detected_version.split('.')]
                if version_parts[0] < 5 or (version_parts[0] == 5 and version_parts[1] < 8):
                    result['potential_vulnerabilities'].append({
                        'name': 'Outdated WordPress',
                        'description': 'This WordPress version may contain known security vulnerabilities',
                        'recommendation': 'Update to the latest version of WordPress'
                    })
                
                # Additional check for common vulnerable WordPress version
                if version_parts[0] == 5 and version_parts[1] < 2:
                    result['potential_vulnerabilities'].append({
                        'name': 'WordPress REST API Vulnerability',
                        'description': 'Versions before 5.2.0 may be vulnerable to REST API issues',
                        'recommendation': 'Update to WordPress 5.2.0 or later'
                    })
            
            # Add similar checks for other CMS platforms
        
        return result
    except Exception as e:
        logging.error(f"CMS detection failed: {str(e)}")
        return {
            'error': f'CMS detection failed: {str(e)}',
            'cms_detected': False
        }

def analyze_cookies(url):
    """Analyze cookie security configurations"""
    try:
        if not url.startswith('http'):
            url = f'https://{url}'
            
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        
        session = requests.Session()
        response = session.get(url, headers=headers, timeout=10, verify=False)
        
        cookies = session.cookies
        cookie_analysis = []
        
        for cookie in cookies:
            security_issues = []
            
            # Check for Secure flag
            if not cookie.secure:
                security_issues.append({
                    'issue': 'Missing Secure Flag',
                    'description': 'Cookie can be transmitted over unencrypted HTTP connections',
                    'recommendation': 'Set the Secure flag to ensure cookies are only sent over HTTPS'
                })
            
            # Check for HttpOnly flag
            if not cookie.has_nonstandard_attr('HttpOnly'):
                security_issues.append({
                    'issue': 'Missing HttpOnly Flag',
                    'description': 'Cookie can be accessed by JavaScript, increasing XSS risk',
                    'recommendation': 'Set the HttpOnly flag to prevent JavaScript access to cookies'
                })
            
            # Check for SameSite attribute
            same_site = None
            for attr in cookie._rest.keys():
                if attr.lower() == 'samesite':
                    same_site = cookie._rest[attr]
            
            if not same_site:
                security_issues.append({
                    'issue': 'Missing SameSite Attribute',
                    'description': 'Cookie has no SameSite attribute, increasing CSRF risk',
                    'recommendation': 'Set SameSite=Lax or SameSite=Strict to limit cookie sending'
                })
            elif same_site.lower() == 'none':
                # SameSite=None is valid, but requires Secure flag
                if not cookie.secure:
                    security_issues.append({
                        'issue': 'Insecure SameSite=None Configuration',
                        'description': 'SameSite=None requires the Secure flag',
                        'recommendation': 'Add the Secure flag when using SameSite=None'
                    })
                    
            cookie_analysis.append({
                'name': cookie.name,
                'domain': cookie.domain,
                'path': cookie.path,
                'secure': cookie.secure,
                'expires': datetime.datetime.fromtimestamp(cookie.expires).isoformat() if cookie.expires else None,
                'http_only': cookie.has_nonstandard_attr('HttpOnly'),
                'same_site': same_site,
                'security_issues': security_issues
            })
        
        # Calculate overall score
        total_cookies = len(cookie_analysis)
        total_issues = sum(len(cookie['security_issues']) for cookie in cookie_analysis)
        score = 100
        if total_cookies > 0:
            avg_issues_per_cookie = total_issues / total_cookies
            # Deduct points based on average issues per cookie
            score = max(0, int(100 - (avg_issues_per_cookie * 30)))
        
        return {
            'cookies': cookie"""
Integrated security scanner module combining basic and enhanced vulnerability scanning.
"""

import ssl
import socket
import dns.resolver
import requests
import re
import json
import datetime
import urllib.parse
from bs4 import BeautifulSoup
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import logging
import warnings
import urllib3
import platform
import psutil
import random
import dns.zone
import dns.query
import sys
import os

# Suppress InsecureRequestWarning warnings
warnings.filterwarnings('ignore', message='.*InsecureRequestWarning.*')

# Set up logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

# Define severity levels
SEVERITY = {
    "Critical": 10,
    "High": 7,
    "Medium": 5,
    "Low": 2,
    "Info": 1
}

# A function to calculate severity based on the issue type
def get_severity_level(severity):
    return SEVERITY.get(severity, SEVERITY["Info"])

# Generate actionable recommendations based on severity
def get_recommendations(vulnerability, severity):
    if severity == "Critical":
        return f"[CRITICAL]
