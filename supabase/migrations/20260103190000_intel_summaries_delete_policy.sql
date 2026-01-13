-- Allow admins to delete intel summaries
CREATE POLICY "Admins can delete summaries"
  ON intel_summaries FOR DELETE
  TO authenticated
  USING (public.has_role(auth.uid(), 'admin'));
