-- Set the cron secret key for intel summary generation
UPDATE public.app_config
SET value = 'e4eded00d269ea626946d863ffbe4b817520c943da2acf22dd0bc4257adc3d1d'
WHERE key = 'cron_secret_key';
