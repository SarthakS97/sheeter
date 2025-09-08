# Sheeter API

Transform your Google Sheets into powerful, secure APIs in minutes. No Google Cloud Console setup required.

# Hackathon Details:
Creator Name: Sarthak S
Theme Addressed: Theme 2
Demo Video Link: (https://youtu.be/MWhGa3dFcsU)
If I had more time: Get the site verified by Google (Usually takes 3-5 weeks)

**Live API:** https://sheeter-2.onrender.com

## Why Sheeter Exists

Working with Google Sheets programmatically has always been unnecessarily complex:

- **Complex Setup**: Google Cloud Console configuration, service accounts, OAuth flows
- **Security Headaches**: Managing credentials, tokens, and permissions
- **Development Friction**: Hours of setup before writing your first line of code
- **Authentication Barriers**: Different auth methods for different use cases

**Sheeter solves this.** One simple OAuth flow gives you a secure API key that works everywhere - from Claude Desktop's MCP to your production applications.

## The Problem Sheeter Solves

```bash
# Traditional Google Sheets API setup:
# 1. Create Google Cloud Project (15+ steps)
# 2. Enable Sheets API
# 3. Create service account or OAuth credentials
# 4. Download keys, configure scopes
# 5. Write authentication code
# 6. Handle token refresh logic
# 7. Deal with rate limits and errors

# With Sheeter:
# 1. Visit sheeter-2.onrender.com
# 2. Sign in with Google
# 3. Get your API key
# 4. Start building
```

## Quick Start

### 1. Get Your API Key
Visit [sheeter-2.onrender.com](https://sheeter-2.onrender.com), sign in with Google, and copy your API key.

### 2. Make Your First Request
```bash
curl -X GET 'https://sheeter-2.onrender.com/api/sheets/YOUR_SHEET_ID' \
  -H 'Authorization: Bearer YOUR_API_KEY'
```

### 3. Start Building
Your Google Sheets are now accessible via a clean REST API.

## API Endpoints

### Authentication
- `GET /auth/status` - Check authentication status
- `GET /auth/google` - Start OAuth flow
- `POST /auth/revoke` - Revoke access

### Spreadsheet Management
- `POST /api/sheets/create` - Create new spreadsheet
- `GET /api/sheets/{id}/metadata` - Get spreadsheet information

### Reading Data
- `GET /api/sheets/{id}` - Read single range
- `POST /api/sheets/{id}/batch-get` - Read multiple ranges

### Writing Data
- `PUT /api/sheets/{id}/values` - Update single range
- `PUT /api/sheets/{id}/batch-update` - Update multiple ranges
- `POST /api/sheets/{id}/append` - Append data

### Advanced Operations
- `DELETE /api/sheets/{id}/values` - Clear range values
- `DELETE /api/sheets/{id}/rows` - Delete rows
- `POST /api/sheets/{id}/batch-update-spreadsheet` - Complex operations (find/replace, formatting)

## Usage Examples

### Create a New Spreadsheet
```bash
curl -X POST 'https://sheeter-2.onrender.com/api/sheets/create' \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer YOUR_API_KEY' \
  -d '{"title": "My API Spreadsheet"}'
```

### Read Sheet Data
```bash
curl -X GET 'https://sheeter-2.onrender.com/api/sheets/1BxiMVs0XRA5nFMdKvBdBZjgmUUqptlbs74OgvE2upms?range=A1:D10' \
  -H 'Authorization: Bearer YOUR_API_KEY'
```

### Write Data
```bash
curl -X PUT 'https://sheeter-2.onrender.com/api/sheets/1BxiMVs0XRA5nFMdKvBdBZjgmUUqptlbs74OgvE2upms/values' \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer YOUR_API_KEY' \
  -d '{
    "range": "A1:B2",
    "values": [["Name", "Age"], ["John", "25"]]
  }'
```

### Append Data
```bash
curl -X POST 'https://sheeter-2.onrender.com/api/sheets/1BxiMVs0XRA5nFMdKvBdBZjgmUUqptlbs74OgvE2upms/append' \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer YOUR_API_KEY' \
  -d '{
    "values": [["Jane", "30"], ["Bob", "35"]]
  }'
```

## Claude Desktop Integration (MCP)

Sheeter works seamlessly with Claude Desktop through the Model Context Protocol:

```json
{
  "mcpServers": {
    "sheeter": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-web"],
      "env": {
        "WEB_BASE_URL": "https://sheeter-2.onrender.com",
        "WEB_API_KEY": "YOUR_API_KEY"
      }
    }
  }
}
```

Now Claude can directly read, write, and manage your spreadsheets through natural language commands.

## Response Format

All endpoints return JSON with consistent structure:

### Success Response
```json
{
  "success": true,
  "data": [...],
  "message": "Operation completed successfully"
}
```

### Error Response
```json
{
  "success": false,
  "error": "Error description"
}
```

## Security

- **OAuth 2.0**: Secure Google authentication
- **JWT Tokens**: Stateless session management
- **Encrypted Storage**: All sensitive data encrypted at rest
- **Scoped Access**: Only access sheets you explicitly authorize
- **HTTPS Only**: All communication encrypted in transit

## Rate Limits

- Reasonable rate limits to ensure fair usage
- Enterprise options available for high-volume use cases

## Why Choose Sheeter Over Direct Google API?

| Feature | Sheeter API | Direct Google API |
|---------|-------------|-------------------|
| Setup Time | 2 minutes | 30+ minutes |
| Google Cloud Account | Not required | Required |
| Credential Management | Single API key | Complex OAuth + Service accounts |
| Token Refresh | Handled automatically | Manual implementation |
| Rate Limit Handling | Built-in | Manual implementation |
| Error Handling | Consistent JSON responses | Various error formats |
| MCP Integration | Native support | Custom implementation needed |

## Support

- **Documentation**: Full OpenAPI specification available
- **Email**: sarthak1509@gmail.com
- **Status**: Check [sheeter-2.onrender.com](https://sheeter-2.onrender.com) for service status

## Legal

- [Terms of Service](https://sheeter-2.onrender.com/terms)
- [Privacy Policy](https://sheeter-2.onrender.com/privacy)

---

**Get started in 2 minutes:** [sheeter-2.onrender.com](https://sheeter-2.onrender.com)

Transform your spreadsheets into APIs today.
