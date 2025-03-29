import requests

def test_route():
    url = 'http://localhost:8000/api/send-premium-email'
    data = {'email': 'joaquimhuelsen@gmail.com'}
    headers = {'Content-Type': 'application/json'}
    
    try:
        response = requests.post(url, json=data, headers=headers)
        print(f"Status Code: {response.status_code}")
        print(f"Response: {response.text}")
    except Exception as e:
        print(f"Error: {str(e)}")

if __name__ == '__main__':
    test_route() 