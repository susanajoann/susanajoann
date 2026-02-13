import requests


API_KEY = '' #input individual google books api key

# Notion API token and database ID
NOTION_TOKEN = '' #token for your notion
DATABASE_ID = '' #database id for the book information


def get_row_id_from_url(url):
  if not url:
    return None
  parts = url.split('/')
  if len(parts) > 0:
    row_id = parts[-1]
    if '-' in row_id:
      row_id = row_id.split('-')[-1]
      return row_id
  else:
    return None


# Function to get book details using API key
def get_book_details(isbn):
  isbn = str(isbn).strip() # Remove leading/trailing spaces
  if len(isbn) != 13:
    print(f"Invalid ISBN: {isbn}")
    return None

  try:

    url = f'https://www.googleapis.com/books/v1/volumes?q=isbn:{isbn}&key={API_KEY}'
    response = requests.get(url)
    data = response.json()
    if 'items' in data and len(data['items']) > 0:
      book = data['items'][0].get('volumeInfo')
      
      return {
        'title': book.get('title', ''),
        'author': ','.join(book.get('authors', [])),
        'publication_date': book.get('publishedDate', ''),
        'page_count': book.get('pageCount', 0),
        'genre': book.get('categories', []),
        'cover_image_url': book.get('imageLinks', {}).get('thumbnail', ''),
        'summary': book.get('description', '')
      }
    else:
      return None
  except Exception as e:
    print(f"Failed to fetch book details for ISBN {isbn}: {str(e)}")
    return None


# Function to update Notion database with book details and cover image
def update_notion_database(row_id, book_details):
  headers = {
    'Authorization': f'Bearer {NOTION_TOKEN}',
    'Content-Type': 'application/json',
    'Notion-Version': '2022-06-28'
  }
  
  if book_details is not None:
    summary = book_details.get('summary', '')[:2000]

    data = {
      'properties': {
        'Author': {'rich_text': [{'text': {'content': book_details['author']}}]},
        'Title': {'title': [{'text': {'content': book_details['title']}}]},
        'Pages': {
          'number': int(book_details.get('page_count', 0)) if book_details.get('page_count') else 0
        },
        'Publication Date': {'date': {'start': book_details['publication_date']}},
        'Genre': {
          'multi_select': [{'name': genre} for genre in book_details.get('genre', [])]
        },
        'Summary': {'rich_text': [{'text': {'content': summary}}]}
      },
      'cover': {
        'type': 'external',
       'external': {
         'url': book_details.get('cover_image_url', '')
        }
      }
    }
    
    
    row_id_without_dashes = row_id.replace('-', '')

    url = f'https://api.notion.com/v1/pages/{row_id_without_dashes}/'
    response = requests.patch(url, headers=headers, json=data)
    if response.status_code == 200:
      print("Book details and cover image updated in Notion database successfully.")
    else:
      print(f"Failed to update book details and cover image in Notion database. Status code: {response.status_code}")


# Fetch the database
def get_notion_database():
  headers = {
    'Authorization': f'Bearer {NOTION_TOKEN}',
    'Content-Type': 'application/json',
    'Notion-Version': '2022-06-28'
  }

  url = 'https://api.notion.com/v1/databases/b3d65cd9cddb49e4aff256040ea39d14/query/'
  response = requests.post(url, headers=headers)
  data = response.json()

  if 'error' in data:
    print(f"Failed to fetch database: {data['error']['message']}")
    return None
  else:
    return data.get('results', [])

def get_row_id_from_isbn(isbn, database):
  for result in database:
    row_isbn = result.get('properties', {}).get('ISBN', {}).get('number', '')
    if row_isbn == isbn:
      return result['id']
  return None

# Fetch the ISBN and title from a row
def get_isbn_and_title_from_row(row):
  isbn = row['properties'].get('ISBN', {}).get('number', None)
  return isbn

# Fetch and update book details
def fetch_and_update_book_details():
  database = get_notion_database()
  for result in database:
    isbn = get_isbn_and_title_from_row(result)
    if isbn is not None:
      row_id = get_row_id_from_isbn(isbn, database)
      book_details = get_book_details(isbn)
      reading_progress = result.get('properties', {}).get('Reading Status', {}).get('select')
      if reading_progress is None and row_id is not None:
        update_notion_database(row_id, book_details)
      else:
        print(f"Skipping update for row {row_id}. Reading progress is filled in as", str(reading_progress.get('name')))
	

# Call the function to fetch and update book details
fetch_and_update_book_details()
