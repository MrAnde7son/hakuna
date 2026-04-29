output "load_balancer_ip" {
  description = "Point your domain's A record to this IP address"
  value       = google_compute_global_address.lb_ip.address
}

output "cloud_run_url" {
  description = "Direct Cloud Run URL (use the load balancer domain in production)"
  value       = google_cloud_run_v2_service.api.uri
}

output "cloud_sql_connection_name" {
  description = "Used by Cloud SQL Auth Proxy: project:region:instance"
  value       = google_sql_database_instance.primary.connection_name
}

output "cloud_sql_private_ip" {
  description = "Private IP of Cloud SQL instance (VPC only)"
  value       = google_sql_database_instance.primary.private_ip_address
  sensitive   = true
}

output "redis_host" {
  description = "Memorystore Redis private IP"
  value       = google_redis_instance.main.host
  sensitive   = true
}

output "artifact_registry_url" {
  description = "Docker registry URL — use this as the prefix for image tags"
  value       = "${var.region}-docker.pkg.dev/${var.project_id}/${google_artifact_registry_repository.main.repository_id}"
}

output "artifact_registry_public_url" {
  description = "Public Docker registry URL — prefix for customer-pulled images (e.g. relay agent)"
  value       = "${var.region}-docker.pkg.dev/${var.project_id}/${google_artifact_registry_repository.public.repository_id}"
}

output "frontend_bucket" {
  description = "Upload built React app here: gsutil -m rsync -r ./frontend/dist gs://<bucket>"
  value       = google_storage_bucket.frontend.name
}

output "scan_files_bucket" {
  description = "GCS bucket for scan file uploads"
  value       = google_storage_bucket.scan_files.name
}

output "db_password_secret" {
  description = "Retrieve DB password: gcloud secrets versions access latest --secret=hakuna-db-password"
  value       = google_secret_manager_secret.db_password.secret_id
}

output "scanner_vm_ip" {
  description = "Private IP of the scanner VM — used by Cloud Run for HAKUNA_SCANNER_URL and VM_SCANNER_URL"
  value       = google_compute_instance.scanners.network_interface[0].network_ip
}

output "scanner_vm_ssh" {
  description = "SSH to the scanner VM via IAP (no public IP needed)"
  value       = "gcloud compute ssh hakuna-scanners --zone=${var.zone} --tunnel-through-iap"
}

output "scanner_vm_logs" {
  description = "View scanner startup log on the VM"
  value       = "gcloud compute ssh hakuna-scanners --zone=${var.zone} --tunnel-through-iap --command='sudo tail -f /var/log/startup-script.log'"
}

output "scanner_docker_status" {
  description = "Check scanner container status on the VM"
  value       = "gcloud compute ssh hakuna-scanners --zone=${var.zone} --tunnel-through-iap --command='cd /opt/hakuna-scanners && sudo docker compose ps'"
}

output "easm_db_migration" {
  description = "Run hakuna-scanner Alembic migrations (run after first apply)"
  value       = "gcloud compute ssh hakuna-scanners --zone=${var.zone} --tunnel-through-iap --command='cd /opt/hakuna-scanners && sudo docker compose exec easm-api alembic upgrade head'"
}

output "lab_vm_ip" {
  description = "Private IP of the lab VM. Point scanner / audit-worker E2E targets at this address. Empty when var.lab_enabled = false."
  value       = try(google_compute_instance.lab[0].network_interface[0].network_ip, "")
}

output "lab_vm_ssh" {
  description = "IAP SSH command for the lab VM."
  value       = "gcloud compute ssh hakuna-lab --zone=${var.zone} --tunnel-through-iap"
}

output "lab_vm_logs" {
  description = "Tail the lab VM startup log."
  value       = "gcloud compute ssh hakuna-lab --zone=${var.zone} --tunnel-through-iap --command='sudo tail -f /var/log/startup-script.log'"
}

output "lab_vm_status" {
  description = "Show lab container status."
  value       = "gcloud compute ssh hakuna-lab --zone=${var.zone} --tunnel-through-iap --command='cd /opt/hakuna-lab && sudo docker compose -f docker-compose.lab.yml ps'"
}

output "lab_vm_refresh" {
  description = "After editing lab files + terraform apply, run this to roll the new bundle onto the VM."
  value       = "gcloud compute ssh hakuna-lab --zone=${var.zone} --tunnel-through-iap --command='sudo systemctl restart hakuna-lab'"
}

output "next_steps" {
  description = "What to do after terraform apply"
  value       = <<-EOT
    ✅ Terraform applied. Next steps:

    1. Point DNS A record for ${var.app_domain} → ${google_compute_global_address.lb_ip.address}
       (SSL cert provisioning starts once DNS resolves — takes 10–20 min)

    2. Run database migrations:
       cloud-sql-proxy ${google_sql_database_instance.primary.connection_name} --port=5432 &
       DB_PASS=$(gcloud secrets versions access latest --secret=hakuna-db-password)
       DATABASE_URL="postgresql+asyncpg://hakuna:$DB_PASS@localhost:5432/hakuna" alembic upgrade head

    3. Deploy frontend:
       cd frontend && npm run build
       gsutil -m rsync -r ./dist gs://${google_storage_bucket.frontend.name}

    4. Verify:
       curl https://${var.app_domain}/api/health
  EOT
}
