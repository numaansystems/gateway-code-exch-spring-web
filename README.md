cat > README.md << 'EOFREADME'
# Azure AD Gateway for Legacy Applications

[![Java](https://img.shields.io/badge/Java-17-blue.svg)](https://openjdk.org/)
[![Spring Boot](https://img.shields. io/badge/Spring%20Boot-3.4.4-green.svg)](https://spring.io/projects/spring-boot)
[![License: MIT](https://img.shields. io/badge/License-MIT-yellow.svg)](https://opensource. org/licenses/MIT)

A production-ready Spring Boot authentication gateway that enables legacy applications to integrate with Azure AD (Microsoft Entra ID) using OAuth2/OpenID Connect without requiring native OAuth2 support in the legacy application.

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Architecture](#architecture)
- [Prerequisites](#prerequisites)
- [Azure AD Configuration](#azure-ad-configuration)
- [Installation](#installation)
- [Configuration](#configuration)
- [Running the Application](#running-the-application)
- [API Endpoints](#api-endpoints)
- [Integration Guide](#integration-guide)
- [Swagger Documentation](#swagger-documentation)
- [Database Authority Lookup](#database-authority-lookup)
- [Security Features](#security-features)
- [Testing](#testing)
- [Production Deployment](#production-deployment)
- [Troubleshooting](#troubleshooting)
- [License](#license)

## Overview

Many legacy applications were built before modern OAuth2/OpenID Connect standards became ubiquitous. These applications often use simple username/password authentication or proprietary SSO solutions that are difficult or impossible to integrate with modern cloud identity providers like Azure AD.

**Azure AD Gateway** solves this problem by acting as an authentication proxy between your legacy application and Azure AD.  The gateway handles the complex OAuth2 authorization code flow, including MFA challenges, and provides a simple REST API that any legacy application can consume.

### The Problem

- **Legacy apps can't handle OAuth2 redirects** - They expect simple login forms
- **Cross-domain authentication is complex** - CORS and cookie issues
- **MFA support requires special handling** - Legacy apps don't have built-in support
- **Token management is complicated** - OAuth2 tokens need refresh logic
- **Security concerns** - Exposing client secrets in frontend code

### The Solution

The gateway uses a **token exchange pattern**:

1. User clicks "Login with Microsoft" in legacy app
2. Legacy app redirects to gateway with a `returnUrl`
3. Gateway handles full OAuth2 flow with Azure AD (including MFA)
4. User completes authentication
5. Gateway creates a short-lived, single-use **exchange token**
6. User redirected back to legacy app with exchange token
7. Legacy app's **backend** validates token via API call
8. Gateway returns user info and authorities
9. Legacy app creates its own session (traditional session management)

This approach keeps OAuth2 complexity in the gateway while providing a simple integration point for legacy applications.

## Features

✅ **Azure AD OAuth2/OIDC Integration** - Full support for Microsoft Entra ID  
✅ **MFA Support** - 2-minute token lifetime accommodates MFA flows  
✅ **Cross-Domain Authentication** - Support for apps on different domains  
✅ **Single-Use Tokens** - Exchange tokens consumed on first validation  
✅ **Authority Merging** - Combines Azure AD roles with optional database authorities  
✅ **Swagger/OpenAPI Documentation** - Interactive API docs with role-based access  
✅ **Health Checks** - Spring Boot Actuator endpoints for monitoring  
✅ **Comprehensive Tests** - 22+ unit and integration tests with >90% coverage  
✅ **Production-Ready** - Secure defaults, comprehensive logging, error handling  
✅ **Flexible Deployment** - Runs as standalone JAR, Docker container, or Kubernetes pod  
✅ **Database Integration (Optional)** - Load additional authorities from database  

## Architecture
┌─────────────────┐ │ Legacy App │ │ (Browser) │ └────────┬────────┘ │ 1. Redirect to /auth/initiate? returnUrl=... ▼ ┌─────────────────────────────────────────┐ │ Azure AD Gateway │ │ (Spring Boot Servlet Application) │ │ │ │ 2. Store returnUrl in session │ │ 3. Redirect to /oauth2/authorization/azure └────────┬────────────────────────────────┘ │ ▼ ┌─────────────────┐ │ Azure AD │ │ (Microsoft) │ │ │ │ 4. User logs │ │ in with MFA │ └────────┬────────┘ │ 5. OAuth2 callback ▼ ┌─────────────────────────────────────────┐ │ Azure AD Gateway │ │ │ │ 6. Extract user info & authorities │ │ 7. Create exchange token (UUID) │ │ 8. Redirect to returnUrl? token=xxx │ └────────┬────────────────────────────────┘ │ ▼ ┌─────────────────┐ │ Legacy App │ │ (Browser) │ │ │ │ 9. Extract │ │ token from │ │ URL params │ └────────┬────────┘ │ 10. Backend API call to /auth/validate-token ▼ ┌─────────────────────────────────────────┐ │ Azure AD Gateway │ │ │ │ 11. Validate token (single-use) │ │ 12. Return user info + authorities │ └─────────────────────────────────────────┘ │ ▼ ┌─────────────────┐ │ Legacy App │ │ (Backend) │ │ │ │ 13. Create │ │ session │ │ 14. Redirect │ │ to app │ └─────────────────┘


## Prerequisites

- **Java 17** or higher ([OpenJDK](https://openjdk.org/) or [Oracle JDK](https://www. oracle.com/java/technologies/downloads/))
- **Maven 3.6+** for building the project
- **Azure AD** (Microsoft Entra ID) account with permissions to register applications
- **MySQL** (optional, only if using database authority lookup)

## Azure AD Configuration

Before running the gateway, you must register an application in Azure AD. 

### Step 1: Register Application

1. Sign in to the [Azure Portal](https://portal. azure.com/)
2. Navigate to **Azure Active Directory** (or **Microsoft Entra ID**)
3. Select **App registrations** → **New registration**
4. Configure:
   - **Name**: `Legacy App Gateway` (or your preferred name)
   - **Supported account types**: 
     - Single tenant (your organization only) - recommended
     - Or multitenant if needed
   - **Redirect URI**: 
     - Type: `Web`
     - URI: `http://localhost:9090/gateway/login/oauth2/code/azure`
     - (Change `localhost` to your actual gateway domain in production)
5. Click **Register**

### Step 2: Configure Authentication

1. In your registered app, go to **Authentication**
2. Under **Implicit grant and hybrid flows**, enable:
   - ✅ **ID tokens** (used for hybrid flows)
3. Under **Advanced settings**:
   - **Allow public client flows**: No
4. Click **Save**

### Step 3: Create Client Secret

1. Go to **Certificates & secrets**
2. Click **New client secret**
3. **Description**: `Gateway Secret`
4. **Expires**: Choose appropriate duration (12-24 months recommended)
5. Click **Add**
6. **⚠️ IMPORTANT**: Copy the secret **Value** immediately (it won't be shown again)

### Step 4: Configure API Permissions

1. Go to **API permissions**
2.  Click **Add a permission** → **Microsoft Graph**
3.  Select **Delegated permissions**
4. Add these permissions:
   - `openid` (Sign users in)
   - `profile` (View users' basic profile)
   - `email` (View users' email address)
5. Click **Add permissions**
6. (Optional) Click **Grant admin consent** if you have admin rights

### Step 5: (Optional) Configure App Roles

If you want to assign roles in Azure AD:

1. Go to **App roles**
2. Click **Create app role**
3. Configure:
   - **Display name**: `Admin`
   - **Allowed member types**: `Users/Groups`
   - **Value**: `ROLE_ADMIN`
   - **Description**: `Administrator role`
4.  Click **Apply**
5.  Repeat for additional roles (`ROLE_USER`, `ROLE_MANAGER`, etc.)

### Step 6: Assign Users

1. Go to **Enterprise applications** in Azure AD
2. Find your application
3. Go to **Users and groups**
4. Click **Add user/group**
5.  Assign users and (if configured) their roles

### Step 7: Note Configuration Values

You'll need these values for the gateway configuration:

- **Tenant ID**: Found in **Overview** page
- **Application (client) ID**: Found in **Overview** page
- **Client Secret**: The value you copied in Step 3

## Installation

```bash
# Clone the repository
git clone https://github.com/numaansystems/gateway-code-exch-spring-web.git
cd gateway-code-exch-spring-web

# Build the project
mvn clean package

# The executable JAR will be in target/gateway-0.1.0.jar
