from ddgs import DDGS

company_name = "Tenable"
# Note: LinkedIn profiles are indexed well under this specific query
query = f'site:linkedin.com/in/ "{company_name}"'

print(f"Searching for {company_name} employees via DDGS...")

try:
    with DDGS() as ddgs:
        # max_results must be a keyword argument in the latest version
        results = ddgs.text(query, max_results=10)
        
        for i, r in enumerate(results):
            print(f"{i+1}. {r['title']}")
            print(f"   URL: {r['href']}\n")
            
except Exception as e:
    print(f"An error occurred: {e}")