/**
 * formatAllowedUntil: when an app allowed for a week stops being allowed, in the viewer's locale
 * ("Fri, Oct 2, 3:14 PM").
 *
 * Why it exists: The note after "Allow Calendar for 7 days" and the rows of Settings ▸ Apps
 * allowed for a week name the same moment, so they word it the same way; a plain module keeps
 * Fast Refresh working for both components.
 */

/**
 * Weekday, date and time without the year: the moment is at most a week away, and the time
 * matters because the week ends at the minute it was allowed, not at midnight. A value that is not
 * a date comes back as it was, rather than as "Invalid Date".
 */
export function formatAllowedUntil(iso: string): string {
  const when = new Date(iso);
  if (Number.isNaN(when.getTime())) return iso;
  return when.toLocaleString(undefined, {
    weekday: "short",
    month: "short",
    day: "numeric",
    hour: "numeric",
    minute: "2-digit",
  });
}
