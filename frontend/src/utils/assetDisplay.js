/**
 * Centralized asset display helpers.
 *
 * Handles all asset types generically: host, web_app, cloud_instance,
 * api_endpoint, identity, container_image, code_repo, k8s_workload,
 * and any user-defined custom type.
 *
 * No switch statements or hardcoded type knowledge — new types work
 * automatically via display_name in asset_identity or first identity value.
 */

/**
 * Get primary display name for any asset.
 * Prefers: display_name in identity > first identity value > hostname > ip > fqdn > fallback.
 */
export function getAssetDisplayName(asset) {
  if (!asset) return 'Unknown';

  // Non-host assets: use identity-based display
  if (asset.asset_type && asset.asset_type !== 'host' && asset.asset_identity) {
    const id = asset.asset_identity;
    if (id.display_name) return id.display_name;
    // Use first meaningful identity value
    const firstVal = Object.values(id).find(v => v && typeof v === 'string');
    if (firstVal) return firstVal;
  }

  // Host assets or fallback
  return asset.hostname || asset.ip || asset.fqdn || `Asset #${asset.id}`;
}

/**
 * Get secondary identifier(s) to show alongside the primary display name.
 * Returns an array of strings (may be empty).
 */
export function getAssetSecondaryInfo(asset) {
  if (!asset) return [];
  const primary = getAssetDisplayName(asset);
  const secondary = [];

  if (asset.asset_type && asset.asset_type !== 'host' && asset.asset_identity) {
    // For non-host: show remaining identity fields that differ from primary
    for (const [, val] of Object.entries(asset.asset_identity)) {
      if (val && typeof val === 'string' && val !== primary && !secondary.includes(val)) {
        secondary.push(val);
      }
    }
    // Also show IP if available (for correlation)
    if (asset.ip && asset.ip !== primary && !secondary.includes(asset.ip)) {
      secondary.push(asset.ip);
    }
    return secondary;
  }

  // Host: show IP and FQDN if different from primary
  if (asset.ip && asset.ip !== primary) secondary.push(asset.ip);
  if (asset.fqdn && asset.fqdn !== primary && asset.fqdn !== asset.hostname) {
    secondary.push(asset.fqdn);
  }
  return secondary;
}

/**
 * Get display name for an asset referenced from a finding.
 * Findings carry asset_hostname/asset_ip rather than the full asset object.
 */
export function getFindingAssetDisplay(finding) {
  if (!finding) return 'Unknown';
  // If the finding carries asset_identity (from enriched API responses), use it
  if (finding.asset_type && finding.asset_type !== 'host' && finding.asset_identity) {
    const id = finding.asset_identity;
    return id.display_name || Object.values(id).find(v => v && typeof v === 'string') || 'Unknown';
  }
  return finding.asset_hostname || finding.asset_ip || 'Unknown';
}

/**
 * Get a scannable/targetable identifier for an asset (IP/hostname/URL).
 * Used when building scan targets or campaign conditions.
 */
export function getAssetTarget(asset) {
  if (!asset) return null;
  if (asset.asset_type === 'web_app' && asset.asset_identity?.url) {
    return asset.asset_identity.url;
  }
  return asset.ip || asset.hostname || asset.fqdn || null;
}

/**
 * Human-readable label for asset_type values.
 */
const TYPE_LABELS = {
  host: 'Host',
  web_app: 'Web App',
  cloud_instance: 'Cloud Instance',
  api_endpoint: 'API Endpoint',
  identity: 'Identity',
  container_image: 'Container Image',
  code_repo: 'Code Repo',
  k8s_workload: 'K8s Workload',
  ai_inference: 'AI Inference',
  ai_service: 'AI Service',
  ai_agent: 'AI Agent',
  ai_notebook: 'AI Notebook',
  vector_db: 'Vector DB',
  iot_gateway: 'IoT Gateway',
  camera: 'Camera',
  nas: 'NAS',
  printer: 'Printer',
  plc: 'PLC',
  scada: 'SCADA',
  smart_building: 'Smart Building',
};

export function getAssetTypeLabel(assetType) {
  if (!assetType) return 'Host';
  return TYPE_LABELS[assetType] || assetType.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
}
