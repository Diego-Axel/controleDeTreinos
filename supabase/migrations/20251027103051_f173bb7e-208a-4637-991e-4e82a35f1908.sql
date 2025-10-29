-- Fix function search_path for validate_email_domain
CREATE OR REPLACE FUNCTION public.validate_email_domain(email text)
RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
  -- Allow admin email or @dominio.com emails
  RETURN email = 'master@gmail.com' OR email ~ '^[^@]+@dominio\.com$';
END;
$$;

-- Fix function search_path for update_updated_at_column
CREATE OR REPLACE FUNCTION public.update_updated_at_column()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = public
AS $$
BEGIN
  NEW.updated_at = now();
  RETURN NEW;
END;
$$;