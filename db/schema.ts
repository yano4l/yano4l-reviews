import { pgTable, serial, text, timestamp, integer, index } from "drizzle-orm/pg-core";

// status: pending_payment -> in_queue -> up_next -> reviewing -> done
export const submissions = pgTable(
  "submissions",
  {
    id: serial().primaryKey(),
    artistName: text("artist_name").notNull(),
    trackTitle: text("track_title").notNull(),
    trackLink: text("track_link").notNull(), // "" when the artist uploaded an audio file instead
    // Uploaded audio file (stored in Netlify Blobs as fixed-size chunks under `${audioUploadId}/<n>`)
    audioUploadId: text("audio_upload_id"),
    audioFilename: text("audio_filename"),
    audioContentType: text("audio_content_type"),
    audioSize: integer("audio_size"),
    genre: text().notNull().default(""),
    email: text().notNull().default(""),
    tier: text().notNull(), // standard | skip | super
    amountCents: integer("amount_cents").notNull(),
    status: text().notNull().default("pending_payment"),
    stripeSessionId: text("stripe_session_id").unique(),
    createdAt: timestamp("created_at").defaultNow().notNull(),
    paidAt: timestamp("paid_at"),
  },
  (t) => [index("submissions_status_idx").on(t.status)],
);

export const loginAttempts = pgTable("login_attempts", {
  id: serial().primaryKey(),
  ip: text().notNull(),
  createdAt: timestamp("created_at").defaultNow().notNull(),
});
