// Email report button
document.getElementById('emailReportBtn').addEventListener('click', function(e) {
    e.preventDefault();
    const email = prompt('Please enter your email address to receive this report:');
    if (email && email.includes('@')) {
        // Get the scan ID from the hidden input
        const scanId = document.getElementById('scan-id').value;
        
        // Create form data
        const formData = new FormData();
        formData.append('scan_id', scanId);
        formData.append('email', email);
        
        // Show loading message
        alert('Sending report to your email...');
        
        // Send AJAX request to the email report API
        fetch('/api/email_report', {
            method: 'POST',
            body: formData
        })
        .then(response => response.json())
        .then(data => {
            if (data.status === 'success') {
                alert(`Thank you! The report has been sent to ${email}.`);
            } else {
                alert(`Error: ${data.message || 'Failed to send email. Please try again.'}`);
            }
        })
        .catch(error => {
            console.error('Error sending email:', error);
            alert('Failed to send email. Please try again.');
        });
    } else if (email) {
        alert('Please enter a valid email address.');
    }
});
