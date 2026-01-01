package com.example.legacyapp.util;

/**
 * Utility class for Azure AD related validation.
 * Java 6 compatible implementation.
 * 
 * @author Legacy App Integration
 * @version 1.0
 */
public class AzureAdUtil {
    
    // UUID format pattern (8-4-4-4-12 hex digits)
    private static final String UUID_PATTERN = 
        "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$";
    
    // Domain name format pattern (common, organizations, consumers, or custom domain)
    private static final String DOMAIN_PATTERN = 
        "^[a-zA-Z0-9][a-zA-Z0-9-\\.]*[a-zA-Z0-9]$";
    
    /**
     * Validate Azure AD tenant ID format.
     * Accepts either UUID format or domain name format.
     * 
     * @param tenantId the tenant ID to validate
     * @return true if valid, false otherwise
     */
    public static boolean isValidTenantId(String tenantId) {
        if (tenantId == null || tenantId.length() == 0) {
            return false;
        }
        
        // Check for UUID format
        if (tenantId.matches(UUID_PATTERN)) {
            return true;
        }
        
        // Check for domain name format
        if (tenantId.matches(DOMAIN_PATTERN)) {
            return true;
        }
        
        return false;
    }
}
