require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const session = require('express-session');
const path = require('path');
const axios = require('axios');
const { Pool } = require('pg');
const crypto = require('crypto');
const pgSession = require('connect-pg-simple')(session);
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const multer = require('multer');
const https = require('https');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');

const app = express();
app.use(helmet({
  contentSecurityPolicy: false, // Disable CSP for now as it might break EJS/inline scripts if not configured carefully
}));
const PORT = process.env.APIPORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'OhubxhJ46DEJWeRdmLERzrDgPYrSsYaCdZ0eE2ITw9pTZDIVODHXicYiZka';
const DEFAULT_ALLOWED_ORIGINS = [
  'http://localhost:8081',
  'http://localhost:19000',
  'exp://localhost:19000',
  'http://localhost:3000',
  'http://localhost:8057',
  'http://localhost:5000',
];
const allowedOrigins = process.env.CORS_ALLOWED_ORIGINS
  ? process.env.CORS_ALLOWED_ORIGINS.split(',').map((origin) => origin.trim()).filter(Boolean)
  : DEFAULT_ALLOWED_ORIGINS;

// Directus API configuration
const url = process.env.DIRECTUS_URL;
const accessToken = process.env.DIRECTUS_TOKEN;

// PostgreSQL connection pool
console.log('Database Connection Settings:', {
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_DATABASE || process.env.DB_NAME,
  port: process.env.DB_PORT,
  node_env: process.env.NODE_ENV,
  db_ssl: process.env.DB_SSL,
  pg_ssl_mode: process.env.PGSSLMODE
});

const pool = new Pool({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_DATABASE || process.env.DB_NAME,
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT,
  max: parseInt(process.env.DB_POOL_MAX, 10) || 50,
  ssl: process.env.DB_SSL === 'true' ? { rejectUnauthorized: false } : false,
});

// Rate Limiters
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10, // Limit each IP to 10 login requests per 15 minutes
  message: {
    error: 'Too Many Requests',
    message: 'Too many login attempts from this IP, please try again after 15 minutes'
  },
  standardHeaders: true,
  legacyHeaders: false,
});

const registerLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 5, // Limit each IP to 5 registration requests per hour
  message: {
    error: 'Too Many Requests',
    message: 'Too many registration attempts from this IP, please try again after an hour'
  },
  standardHeaders: true,
  legacyHeaders: false,
});

// Middleware
app.use(express.static(path.join(__dirname, 'public')));
app.set('view engine', 'ejs');
app.use(cookieParser());
app.use(bodyParser.urlencoded({ extended: true, limit: '50mb' }));
app.use(bodyParser.json({ limit: '50mb' }));
app.use(cors({
  origin: (origin, callback) => {
    // Native mobile requests often omit Origin entirely.
    if (!origin) return callback(null, true);
    if (allowedOrigins.includes(origin)) return callback(null, true);
    return callback(new Error(`CORS blocked for origin: ${origin}`));
  },
  credentials: true,
}));

const SESSION_SECRET = process.env.SESSION_SECRET || 'sqT_d_qxWqHyXS6Yk7Me8APygz3EjFE8';

app.use(session({
  store: new pgSession({
    pool: pool,
    tableName: 'session',
  }),
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
  },
}));

// Serve static files
app.use(express.static(path.join(__dirname, 'public')));

// ============================================
// HELPER FUNCTIONS
// ============================================

/**
 * Query function for Directus API
 */
async function query(path, config) {
    const res = await axios(`${url}${path}`, {
        headers: {
            "Authorization": `Bearer ${accessToken}`,
            "Content-Type": "application/json",
        },
        ...config
    });
    return res;
}

/**
 * Sanitize limit parameter for Directus API
 */
function sanitizeLimit(limit, defaultValue = 10, maxLimit = 100) {
  const parsed = parseInt(limit, 10);
  if (isNaN(parsed) || parsed <= 0) return defaultValue;
  return Math.min(parsed, maxLimit);
}

/**
 * Sanitize sort parameter for Directus API
 * Allows only alphanumeric characters, underscores, and a leading minus sign
 */
function sanitizeSort(sort, defaultValue = '-start_time') {
  if (!sort || typeof sort !== 'string') return defaultValue;
  // Regex: optional leading minus, then word characters
  const safeSortPattern = /^-?\w+$/;
  if (!safeSortPattern.test(sort)) return defaultValue;
  return sort;
}

/**
 * Hash password using bcrypt
 */
async function hashPassword(password) {
  const salt = await bcrypt.genSalt(10);
  return await bcrypt.hash(password, salt);
}

/**
 * Verify password
 */
async function verifyPassword(password, hashedPassword) {
  return await bcrypt.compare(password, hashedPassword);
}

/**
 * Generate JWT token
 */
function generateToken(payload) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: '7d' });
}

/**
 * Verify JWT token
 */
function verifyToken(token) {
  try {
    return jwt.verify(token, JWT_SECRET);
  } catch (error) {
    return null;
  }
}

// Patrol lifecycle statuses used by the mobile flow.
const PATROL_STATUS = {
  ACTIVE_ON_PATROL: 'active_on_patrol',
  INACTIVE_NOT_STARTED: 'inactive_patrol_not_started',
  LOGGED_OUT_ON_PATROL: 'logged_out_on_patrol',
  COMPLETED: 'completed',
  LEGACY_ACTIVE: 'active',
};

const ONGOING_PATROL_STATUSES = new Set([
  PATROL_STATUS.ACTIVE_ON_PATROL,
  PATROL_STATUS.LOGGED_OUT_ON_PATROL,
  PATROL_STATUS.LEGACY_ACTIVE,
]);

const normalizePatrolLifecycleStatus = (status) => {
  if (status === PATROL_STATUS.LEGACY_ACTIVE) {
    return PATROL_STATUS.ACTIVE_ON_PATROL;
  }
  if (
    status === PATROL_STATUS.ACTIVE_ON_PATROL ||
    status === PATROL_STATUS.INACTIVE_NOT_STARTED ||
    status === PATROL_STATUS.LOGGED_OUT_ON_PATROL ||
    status === PATROL_STATUS.COMPLETED
  ) {
    return status;
  }
  return PATROL_STATUS.INACTIVE_NOT_STARTED;
};

const getLatestOngoingPatrol = async (userId) => {
  try {
    const patrolsResponse = await query(
      `/items/patrols?filter[user_id][_eq]=${encodeURIComponent(userId)}&sort=-start_time&limit=25`
    );
    const patrols = patrolsResponse.data.data || [];
    const ongoing = patrols.find(
      (patrol) =>
        !patrol.end_time &&
        ONGOING_PATROL_STATUSES.has(normalizePatrolLifecycleStatus(patrol.status))
    );
    return ongoing || null;
  } catch (error) {
    console.error(`Error finding ongoing patrol for user ${userId}:`, error);
    return null;
  }
};

const ADMIN_NOTIFICATION_TYPE = {
  LOG_CREATED: 'log_created',
  GUARD_LATE_START: 'guard_late_start',
  GUARD_LOGGED_OUT_ON_PATROL: 'guard_logged_out_on_patrol',
  PATROL_ENDED_EARLY: 'patrol_ended_early',
  PATROL_NOT_ENDED_AFTER_SHIFT: 'patrol_not_ended_after_shift',
};

const safeDate = (value) => {
  if (!value) return null;
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? null : parsed;
};

const parseShiftTimeOnReferenceDate = (timeValue, referenceDate) => {
  if (!timeValue || typeof timeValue !== 'string') return null;
  const parts = String(timeValue).trim().split(':');
  if (parts.length < 2) return null;

  const hours = Number(parts[0]);
  const minutes = Number(parts[1]);
  const seconds = parts.length > 2 ? Number(parts[2]) : 0;

  if (
    !Number.isFinite(hours) || !Number.isFinite(minutes) || !Number.isFinite(seconds) ||
    hours < 0 || hours > 23 || minutes < 0 || minutes > 59 || seconds < 0 || seconds > 59
  ) {
    return null;
  }

  const date = new Date(referenceDate);
  if (Number.isNaN(date.getTime())) return null;
  date.setHours(hours, minutes, seconds, 0);
  return date;
};

const getGuardDisplayName = (guard) => {
  const firstName = String(guard?.first_name || '').trim();
  const lastName = String(guard?.last_name || '').trim();
  const fullName = `${firstName} ${lastName}`.trim();
  return fullName || 'Unknown Guard';
};

const getNotificationPriorityForLogCategory = (category) => {
  if (category === 'incident') return 'high';
  if (category === 'unusual') return 'medium';
  return 'low';
};

const buildAdminNotifications = async (inviteCode, limit = 100) => {
  const guardsResponse = await query(
    `/items/users?filter[role][_eq]=guard&filter[invite_code][_eq]=${encodeURIComponent(inviteCode)}&fields=id,first_name,last_name,phone`
  );
  const guards = guardsResponse.data.data || [];
  if (!guards.length) return [];

  const locationsById = new Map();
  try {
    const locationsResponse = await query(
      `/items/locations?filter[organization][_eq]=${encodeURIComponent(inviteCode)}&fields=id,name`
    );
    const locations = locationsResponse.data.data || [];
    for (const location of locations) {
      locationsById.set(location.id, location.name);
    }
  } catch (locationError) {
    console.error('Error fetching locations while building admin notifications:', locationError);
  }

  const notifications = [];
  const now = new Date();

  for (const guard of guards) {
    const guardId = guard.id;
    const guardName = getGuardDisplayName(guard);

    let assignment = null;
    let patrols = [];
    let logs = [];

    try {
      const assignmentResponse = await query(
        `/items/assignments?filter[user_id][_eq]=${encodeURIComponent(guardId)}&sort=-date_updated&limit=1`
      );
      assignment = (assignmentResponse.data.data || [])[0] || null;
    } catch (assignmentError) {
      console.error(`Error fetching assignment for guard ${guardId} during notification build:`, assignmentError);
    }

    try {
      const patrolsResponse = await query(
        `/items/patrols?filter[user_id][_eq]=${encodeURIComponent(guardId)}&sort=-start_time&limit=30`
      );
      patrols = patrolsResponse.data.data || [];
    } catch (patrolError) {
      console.error(`Error fetching patrols for guard ${guardId} during notification build:`, patrolError);
    }

    try {
      const logsResponse = await query(
        `/items/logs?filter[user_id][_eq]=${encodeURIComponent(guardId)}&sort=-timestamp&limit=30`
      );
      logs = logsResponse.data.data || [];
    } catch (logError) {
      console.error(`Error fetching logs for guard ${guardId} during notification build:`, logError);
    }

    const assignmentLocationValue = assignment?.location || '';
    const resolvedLocation = assignmentLocationValue
      ? (locationsById.get(assignmentLocationValue) || assignmentLocationValue)
      : 'Unknown Location';

    for (const log of logs) {
      const eventDate = safeDate(log.timestamp) || safeDate(log.date_created) || now;
      notifications.push({
        id: `log_created:${log.id}`,
        type: ADMIN_NOTIFICATION_TYPE.LOG_CREATED,
        priority: getNotificationPriorityForLogCategory(log.category),
        title: `New log created by ${guardName}`,
        message: log.title ? `${log.title}: ${log.description || ''}`.trim() : (log.description || 'A new guard log was submitted'),
        guard_id: guardId,
        guard_name: guardName,
        patrol_id: log.patrol_id || null,
        log_id: log.id || null,
        location: log.location || resolvedLocation,
        event_time: eventDate.toISOString(),
      });
    }

    if (assignment?.start_time) {
      const shiftStartToday = parseShiftTimeOnReferenceDate(assignment.start_time, now);
      if (shiftStartToday) {
        const lateThreshold = new Date(shiftStartToday.getTime() + (15 * 60 * 1000));
        const hasStartedTodayPatrol = patrols.some((patrol) => {
          const patrolStart = safeDate(patrol.start_time);
          return patrolStart && patrolStart.getTime() >= shiftStartToday.getTime();
        });

        if (now.getTime() > lateThreshold.getTime() && !hasStartedTodayPatrol) {
          const dateKey = shiftStartToday.toISOString().slice(0, 10);
          notifications.push({
            id: `guard_late_start:${guardId}:${dateKey}`,
            type: ADMIN_NOTIFICATION_TYPE.GUARD_LATE_START,
            priority: 'high',
            title: `${guardName} is late for patrol`,
            message: `No patrol has started at least 15 minutes after assigned start time (${assignment.start_time}).`,
            guard_id: guardId,
            guard_name: guardName,
            patrol_id: null,
            log_id: null,
            location: resolvedLocation,
            event_time: lateThreshold.toISOString(),
          });
        }
      }
    }

    for (const patrol of patrols) {
      const patrolId = patrol.id || '';
      const patrolStart = safeDate(patrol.start_time);
      const patrolEnd = safeDate(patrol.end_time);
      const normalizedStatus = normalizePatrolLifecycleStatus(patrol.status);
      const shiftEndForPatrolDay =
        assignment?.end_time && patrolStart
          ? parseShiftTimeOnReferenceDate(assignment.end_time, patrolStart)
          : null;

      if (!patrolEnd && normalizedStatus === PATROL_STATUS.LOGGED_OUT_ON_PATROL) {
        const statusEventDate = safeDate(patrol.date_updated) || patrolStart || now;
        notifications.push({
          id: `guard_logged_out_on_patrol:${patrolId}`,
          type: ADMIN_NOTIFICATION_TYPE.GUARD_LOGGED_OUT_ON_PATROL,
          priority: 'high',
          title: `${guardName} logged out while on patrol`,
          message: 'This patrol is still open and marked as logged out on patrol.',
          guard_id: guardId,
          guard_name: guardName,
          patrol_id: patrolId || null,
          log_id: null,
          location: patrol.location || resolvedLocation,
          event_time: statusEventDate.toISOString(),
        });
      }

      if (
        patrolEnd &&
        shiftEndForPatrolDay &&
        shiftEndForPatrolDay.getTime() - patrolEnd.getTime() > (60 * 1000)
      ) {
        notifications.push({
          id: `patrol_ended_early:${patrolId}`,
          type: ADMIN_NOTIFICATION_TYPE.PATROL_ENDED_EARLY,
          priority: 'medium',
          title: `${guardName} ended patrol early`,
          message: `Patrol ended before assigned end time (${assignment.end_time}).`,
          guard_id: guardId,
          guard_name: guardName,
          patrol_id: patrolId || null,
          log_id: null,
          location: patrol.location || resolvedLocation,
          event_time: patrolEnd.toISOString(),
        });
      }

      if (!patrolEnd && shiftEndForPatrolDay) {
        const allowedEnd = new Date(shiftEndForPatrolDay.getTime() + (15 * 60 * 1000));
        if (now.getTime() > allowedEnd.getTime()) {
          notifications.push({
            id: `patrol_not_ended_after_shift:${patrolId}`,
            type: ADMIN_NOTIFICATION_TYPE.PATROL_NOT_ENDED_AFTER_SHIFT,
            priority: 'high',
            title: `${guardName} has not ended patrol`,
            message: `Patrol is still active 15 minutes after assigned end time (${assignment.end_time}).`,
            guard_id: guardId,
            guard_name: guardName,
            patrol_id: patrolId || null,
            log_id: null,
            location: patrol.location || resolvedLocation,
            event_time: allowedEnd.toISOString(),
          });
        }
      }
    }
  }

  notifications.sort((a, b) => {
    const aTime = safeDate(a.event_time)?.getTime() || 0;
    const bTime = safeDate(b.event_time)?.getTime() || 0;
    return bTime - aTime;
  });

  return notifications.slice(0, Math.max(1, Number(limit) || 100));
};

const EXPO_PUSH_URL = 'https://exp.host/--/api/v2/push/send';
const PERIODIC_PUSH_SCAN_MS = 60 * 1000;
const PERIODIC_PUSH_STARTUP_DELAY_MS = 15 * 1000;
let periodicPushScanInterval = null;

const buildDirectusQueryString = (params = {}) =>
  Object.entries(params)
    .filter(([, value]) => value !== undefined && value !== null && value !== '')
    .map(([key, value]) => `${encodeURIComponent(key)}=${encodeURIComponent(String(value))}`)
    .join('&');

const fetchAllDirectusItems = async (collection, params = {}, pageSize = 200) => {
  const items = [];
  let offset = 0;

  while (true) {
    const queryString = buildDirectusQueryString({
      ...params,
      limit: pageSize,
      offset,
    });
    const response = await query(`/items/${collection}?${queryString}`);
    const page = response?.data?.data || [];
    items.push(...page);
    if (page.length < pageSize) break;
    offset += pageSize;
  }

  return items;
};

const upsertAdminPushToken = async ({ userId, inviteCode, expoPushToken, platform }) => {
  const userIdText = String(userId);
  const existingResponse = await query(
    `/items/admin_push_tokens?${buildDirectusQueryString({
      'filter[user_id][_eq]': userIdText,
      fields: 'id',
      limit: 1,
    })}`
  );
  const existing = (existingResponse?.data?.data || [])[0];
  const payload = {
    user_id: userIdText,
    invite_code: String(inviteCode),
    expo_push_token: String(expoPushToken),
    platform: platform ? String(platform) : null,
    updated_at: new Date().toISOString(),
  };

  if (existing?.id) {
    await query(`/items/admin_push_tokens/${encodeURIComponent(existing.id)}`, {
      method: 'PATCH',
      data: payload,
    });
    return;
  }

  await query('/items/admin_push_tokens', {
    method: 'POST',
    data: payload,
  });
};

const deleteAdminPushToken = async ({ userId }) => {
  const matches = await fetchAllDirectusItems('admin_push_tokens', {
    'filter[user_id][_eq]': String(userId),
    fields: 'id',
  });

  for (const row of matches) {
    if (!row?.id) continue;
    await query(`/items/admin_push_tokens/${encodeURIComponent(row.id)}`, {
      method: 'DELETE',
    });
  }
};

const getAdminPushTokensByInviteCode = async (inviteCode) => {
  const rows = await fetchAllDirectusItems('admin_push_tokens', {
    'filter[invite_code][_eq]': String(inviteCode),
    fields: 'id,user_id,expo_push_token',
  });
  return rows || [];
};

const hasDispatchRecord = async (eventKey) => {
  const response = await query(
    `/items/push_dispatches?${buildDirectusQueryString({
      'filter[event_key][_eq]': String(eventKey),
      fields: 'id',
      limit: 1,
    })}`
  );
  return ((response?.data?.data || []).length || 0) > 0;
};

const recordDispatch = async ({ eventKey, eventType, inviteCode, payload }) => {
  await query('/items/push_dispatches', {
    method: 'POST',
    data: {
      event_key: String(eventKey),
      event_type: String(eventType),
      invite_code: String(inviteCode),
      payload: payload || {},
      sent_at: new Date().toISOString(),
    },
  });
};

const sendExpoPushNotifications = async (messages) => {
  if (!Array.isArray(messages) || messages.length === 0) return null;
  try {
    const response = await axios.post(EXPO_PUSH_URL, messages, {
      headers: {
        'Content-Type': 'application/json',
      },
      timeout: 10000,
    });
    return response?.data || null;
  } catch (error) {
    console.error('Error sending Expo push notifications:', error?.response?.data || error.message || error);
    return null;
  }
};

const dispatchPushToOrganization = async ({
  inviteCode,
  eventType,
  eventKey,
  title,
  body,
  data,
  priority = 'default',
}) => {
  if (!inviteCode || !eventKey || !title || !body) return { skipped: true, reason: 'invalid_payload' };

  const alreadySent = await hasDispatchRecord(eventKey);
  if (alreadySent) return { skipped: true, reason: 'already_dispatched' };

  const tokens = await getAdminPushTokensByInviteCode(inviteCode);
  if (!tokens.length) return { skipped: true, reason: 'no_registered_tokens' };

  const messages = tokens.map((row) => ({
    to: row.expo_push_token,
    sound: 'default',
    title,
    body,
    data: data || {},
    priority,
    channelId: 'patrollink-alerts',
  }));

  const expoResponse = await sendExpoPushNotifications(messages);
  const responseItems = Array.isArray(expoResponse?.data) ? expoResponse.data : [];

  for (let i = 0; i < responseItems.length; i += 1) {
    const item = responseItems[i];
    const tokenRow = tokens[i];
    if (!item || !tokenRow) continue;
    const errorDetails = item?.details?.error || '';
    if (item.status === 'error' && (errorDetails === 'DeviceNotRegistered' || errorDetails === 'InvalidCredentials')) {
      await deleteAdminPushToken({ userId: tokenRow.user_id });
    }
  }

  await recordDispatch({
    eventKey,
    eventType,
    inviteCode,
    payload: { title, body, data: data || {}, response: expoResponse || null },
  });

  return { dispatched: true, recipients: tokens.length };
};

const getLatestAssignmentForGuard = async (guardId) => {
  const response = await query(
    `/items/assignments?filter[user_id][_eq]=${encodeURIComponent(guardId)}&sort=-date_updated&limit=1`
  );
  return (response?.data?.data || [])[0] || null;
};

const resolveLocationName = async (inviteCode, locationId) => {
  if (!locationId) return 'Unknown Location';
  try {
    const response = await query(
      `/items/locations?filter[id][_eq]=${encodeURIComponent(locationId)}&filter[organization][_eq]=${encodeURIComponent(inviteCode)}&fields=id,name&limit=1`
    );
    const location = (response?.data?.data || [])[0] || null;
    return location?.name || locationId;
  } catch (_error) {
    return locationId;
  }
};

const evaluatePeriodicPushRulesForOrganization = async (inviteCode) => {
  if (!inviteCode) return;

  let guards = [];
  try {
    const guardsResponse = await query(
      `/items/users?filter[role][_eq]=guard&filter[invite_code][_eq]=${encodeURIComponent(inviteCode)}&fields=id,first_name,last_name`
    );
    guards = guardsResponse.data.data || [];
  } catch (guardError) {
    console.error('Failed fetching guards for periodic push scan:', guardError);
    return;
  }

  const now = new Date();

  for (const guard of guards) {
    const guardId = guard.id;
    const guardName = getGuardDisplayName(guard);
    let assignment = null;
    let patrols = [];

    try {
      assignment = await getLatestAssignmentForGuard(guardId);
    } catch (assignmentError) {
      console.error(`Failed fetching assignment for guard ${guardId} in periodic scan:`, assignmentError);
    }

    try {
      const patrolResponse = await query(
        `/items/patrols?filter[user_id][_eq]=${encodeURIComponent(guardId)}&sort=-start_time&limit=20`
      );
      patrols = patrolResponse?.data?.data || [];
    } catch (patrolError) {
      console.error(`Failed fetching patrols for guard ${guardId} in periodic scan:`, patrolError);
    }

    const locationName = await resolveLocationName(inviteCode, assignment?.location || '');

    if (assignment?.start_time) {
      const shiftStart = parseShiftTimeOnReferenceDate(assignment.start_time, now);
      if (shiftStart) {
        const lateThreshold = new Date(shiftStart.getTime() + (15 * 60 * 1000));
        const startedShiftPatrol = patrols.some((patrol) => {
          const start = safeDate(patrol.start_time);
          return start && start.getTime() >= shiftStart.getTime();
        });

        if (now.getTime() > lateThreshold.getTime() && !startedShiftPatrol) {
          const keyDay = shiftStart.toISOString().slice(0, 10);
          await dispatchPushToOrganization({
            inviteCode,
            eventType: ADMIN_NOTIFICATION_TYPE.GUARD_LATE_START,
            eventKey: `${ADMIN_NOTIFICATION_TYPE.GUARD_LATE_START}:${guardId}:${keyDay}`,
            title: `${guardName} is late`,
            body: `No patrol started 15+ min after assigned start (${assignment.start_time}).`,
            data: {
              type: ADMIN_NOTIFICATION_TYPE.GUARD_LATE_START,
              guard_id: guardId,
              guard_name: guardName,
              location: locationName,
            },
            priority: 'high',
          });
        }
      }
    }

    for (const patrol of patrols) {
      const patrolStart = safeDate(patrol.start_time);
      const patrolEnd = safeDate(patrol.end_time);
      if (!assignment?.end_time || !patrolStart || patrolEnd) continue;

      const shiftEndForDay = parseShiftTimeOnReferenceDate(assignment.end_time, patrolStart);
      if (!shiftEndForDay) continue;
      const overdueThreshold = new Date(shiftEndForDay.getTime() + (15 * 60 * 1000));

      if (now.getTime() > overdueThreshold.getTime()) {
        await dispatchPushToOrganization({
          inviteCode,
          eventType: ADMIN_NOTIFICATION_TYPE.PATROL_NOT_ENDED_AFTER_SHIFT,
          eventKey: `${ADMIN_NOTIFICATION_TYPE.PATROL_NOT_ENDED_AFTER_SHIFT}:${patrol.id}:${overdueThreshold.toISOString()}`,
          title: `${guardName} patrol not ended`,
          body: `Patrol still active 15+ min after assigned end (${assignment.end_time}).`,
          data: {
            type: ADMIN_NOTIFICATION_TYPE.PATROL_NOT_ENDED_AFTER_SHIFT,
            guard_id: guardId,
            guard_name: guardName,
            patrol_id: patrol.id,
            location: patrol.location || locationName,
          },
          priority: 'high',
        });
      }
    }
  }
};

const runPeriodicPushScan = async () => {
  try {
    const rows = await fetchAllDirectusItems('admin_push_tokens', {
      fields: 'invite_code',
    });
    const inviteCodes = [...new Set((rows || []).map((row) => row.invite_code).filter(Boolean))];
    for (const inviteCode of inviteCodes) {
      await evaluatePeriodicPushRulesForOrganization(inviteCode);
    }
  } catch (error) {
    if (error?.code === 'ECONNREFUSED') {
      console.warn('Periodic push scan skipped: Directus is not ready yet. Will retry on next cycle.');
      return;
    }
    console.error('Periodic push scan failed:', error);
  }
};

// ============================================
// AUTH MIDDLEWARE
// ============================================

/**
 * Check session middleware (for session-based auth - API)
 */
const checkSession = (req, res, next) => {
  if (req.session && req.session.user) {
    next();
  } else {
    res.status(401).json({ error: 'Unauthorized', message: 'Please login to access this resource' });
  }
};

/**
 * Require Auth middleware (for web views)
 * Denies access to non-admin users
 */
const requireAuth = (req, res, next) => {
  if (req.session && req.session.user) {
    if (req.session.user.role !== 'admin') {
      return res.status(403).send('Access denied. Admin privileges required.');
    }
    next();
  } else {
    req.session.returnTo = req.originalUrl;
    res.redirect('/login');
  }
};

/**
 * Verify JWT token middleware
 */
const verifyTokenMiddleware = (req, res, next) => {
  const authHeader = req.headers.authorization;
  
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized', message: 'No token provided' });
  }
  
  const token = authHeader.split(' ')[1];
  const decoded = verifyToken(token);
  
  if (!decoded) {
    return res.status(401).json({ error: 'Unauthorized', message: 'Invalid or expired token' });
  }
  
  req.user = decoded;
  next();
};

// ============================================
// AUTH ROUTES
// ============================================

/**
 * POST /api/register
 * Register a new user
 * Body: { firstName, lastName, phone, password, role?, companyCode? }
 */
async function signUp(userData) {

  const response = await query('/items/users', {
    method: 'POST',
    data: userData,
  });

  return response.data;
}

app.post('/api/register', registerLimiter, async (req, res) => {
  try {
    const { firstName, lastName, phone, password, role, companyCode } = req.body || {};

    // Validate required fields
    if (!firstName || !lastName || !phone || !password) {
      return res.status(400).json({ 
        error: 'Validation Error', 
        message: 'Please fill in all required fields' 
      });
    }

    const hashedPassword = await hashPassword(password);

    // Prepare user data for Directus (Directus handles password hashing)
    const userData = {
      first_name: firstName,
      last_name: lastName,
      phone: phone,
      password: hashedPassword,
      role: role || 'guard',
      invite_code: companyCode || 'null',
      status: 'active',
    };

    // Register user in Directus
    const newUser = await signUp(userData);

    // Return success (without password)
    res.status(201).json({
      message: 'User registered successfully',
      user: newUser
    });
  } catch (error) {
    console.error('Registration Error:', error);
    
    // Handle duplicate entry error
    if (error.message?.includes('UNIQUE')) {
      return res.status(409).json({ 
        error: 'Conflict', 
        message: 'User with this phone number already exists' 
      });
    }
    
    res.status(500).json({ 
      error: 'Internal Server Error', 
      message: 'Failed to register user' 
    });
  }
});

/**
 * GET /api/assignments
 * Get all assignments (admin/supervisor only)
 */
app.get('/api/assignments', verifyTokenMiddleware, async (req, res) => {
  try {
    // Fetch assignments from Directus with guard info
    const response = await query('/items/assignments');
    // console.log(response)
    res.json({
      assignments: response.data.data
    });
  } catch (error) {
    console.error('Error fetching assignments:', error);
    res.status(500).json({
      error: 'Internal Server Error',
      message: 'Failed to fetch assignments'
    });
  }
});

/**
 * GET /api/my-assignments
 * Get assignments for the logged-in guard
 */
app.get('/api/my-assignments', verifyTokenMiddleware, async (req, res) => {
  try {
    const userId = req.user.id;

    // Fetch assignments for this guard from Directus
    const response = await query(`/items/assignments?filter[user_id][_eq]=${userId}`);

    res.json({
      assignments: response.data.data
    });
  } catch (error) {
    console.error('Error fetching my assignments:', error);
    res.status(500).json({
      error: 'Internal Server Error',
      message: 'Failed to fetch assignments'
    });
  }
});

/**
 * PUT /api/my-assignments
 * Update assignment for the logged-in guard
 * Body: { location, assigned_areas, start_time, end_time }
 */
app.put('/api/my-assignments', verifyTokenMiddleware, async (req, res) => {
  try {
    const userId = req.user.id;
    const { location, assigned_areas, start_time, end_time } = req.body || {};

    // Validate required fields
    if (!location || !assigned_areas || !start_time || !end_time) {
      return res.status(400).json({
        error: 'Validation Error',
        message: 'All fields are required: location, assigned_areas, start_time, end_time'
      });
    }

    // Fetch the assignment for this user
    const response = await query(`/items/assignments?filter[user_id][_eq]=${userId}`);

    if (!response.data.data || response.data.data.length === 0) {
      return res.status(404).json({
        error: 'Not Found',
        message: 'No assignment found for this user'
      });
    }

    const assignment = response.data.data[0]; // Assuming one assignment per user

    // Update the assignment
    const updateData = {
      location,
      assigned_areas,
      start_time,
      end_time,
      date_updated: new Date().toISOString()
    };

    await query(`/items/assignments/${assignment.id}`, {
      method: 'PATCH',
      data: updateData
    });

    res.json({ message: 'Assignment updated successfully' });
  } catch (error) {
    console.error('Error updating assignment:', error);
    res.status(500).json({
      error: 'Internal Server Error',
      message: 'Failed to update assignment'
    });
  }
});

/**
 * GET /api/locations
 * Get locations for the logged-in user's organization
 */
app.get('/api/locations', verifyTokenMiddleware, async (req, res) => {
  try {
    const inviteCode = req.user.invite_code;

    // Fetch locations where organization.invite_code matches user's invite_code
    const response = await query(`/items/locations?filter[organization][_eq]=${inviteCode}`);

    res.json({
      locations: response.data.data
    });

    // console.log("Locations data",response.data.data)
  } catch (error) {
    console.error('Error fetching locations:', error);
    res.status(500).json({
      error: 'Internal Server Error',
      message: 'Failed to fetch locations'
    });
  }
});

/**
 * POST /api/login
 * Login with phone and password
 * Body: { phone, password }
 */
app.post('/api/login', loginLimiter, async (req, res) => {
  try {
    const { phone, password } = req.body || {};

    // Validate input
    if (!phone || !password) {
      return res.status(400).json({ 
        error: 'Validation Error', 
        message: 'Please provide phone number and password' 
      });
    }

    // Find user in Directus by phone
    const queryUrl = `/items/users?filter[phone][_eq]=${encodeURIComponent(phone)}`;
    // console.log("Query URL:", `${url}${queryUrl}`);
    const users = await query(queryUrl);

    // console.log("Full response:", users);
    // console.log("Response data:", users.data);
    // console.log("Found users:", users.data.data);

    if (!users.data.data || users.data.data.length === 0) {
      return res.status(401).json({ 
        error: 'Unauthorized', 
        message: 'Invalid phone number or password' 
      });
    }

    const user = users.data.data[0];

    // Verify password
    const isValidPassword = await verifyPassword(password, user.password);
    if (!isValidPassword) {
      return res.status(401).json({ 
        error: 'Unauthorized', 
        message: 'Invalid phone number or password' 
      });
    }

    // Fetch assignments for guards
    let assignments = [];
    let ongoingPatrol = null;
    let patrolStatus = PATROL_STATUS.INACTIVE_NOT_STARTED;
    if (user.role === 'guard') {
      try {
        const assignmentsResponse = await query(`/items/assignments?filter[user_id][_eq]=${user.id}`);
        assignments = assignmentsResponse.data.data || [];
      } catch (assignmentError) {
        console.error('Error fetching guard assignments:', assignmentError);
        assignments = [];
      }

      // If an unfinished patrol exists from a previous app session/device shutdown,
      // mark it as logged-out-on-patrol so clients can communicate that state.
      ongoingPatrol = await getLatestOngoingPatrol(user.id);
      if (ongoingPatrol && !ongoingPatrol.end_time) {
        patrolStatus = normalizePatrolLifecycleStatus(ongoingPatrol.status);
        if (patrolStatus === PATROL_STATUS.ACTIVE_ON_PATROL) {
          try {
            const patchResponse = await query(`/items/patrols/${encodeURIComponent(ongoingPatrol.id)}`, {
              method: 'PATCH',
              data: { status: PATROL_STATUS.LOGGED_OUT_ON_PATROL },
            });
            ongoingPatrol = patchResponse?.data?.data || ongoingPatrol;
            patrolStatus = PATROL_STATUS.LOGGED_OUT_ON_PATROL;
            await dispatchPushToOrganization({
              inviteCode: user.invite_code,
              eventType: ADMIN_NOTIFICATION_TYPE.GUARD_LOGGED_OUT_ON_PATROL,
              eventKey: `${ADMIN_NOTIFICATION_TYPE.GUARD_LOGGED_OUT_ON_PATROL}:${ongoingPatrol.id}`,
              title: `${getGuardDisplayName(user)} logged out while on patrol`,
              body: 'A guard has an open patrol that is now marked as logged out on patrol.',
              data: {
                type: ADMIN_NOTIFICATION_TYPE.GUARD_LOGGED_OUT_ON_PATROL,
                guard_id: user.id,
                guard_name: getGuardDisplayName(user),
                patrol_id: ongoingPatrol.id,
                location: ongoingPatrol.location || 'Unknown Location',
              },
              priority: 'high',
            });
          } catch (statusPatchError) {
            console.error('Error patching patrol status on login:', statusPatchError);
            patrolStatus = PATROL_STATUS.ACTIVE_ON_PATROL;
          }
        }
      }
    }

    // Generate JWT token
    const tokenPayload = {
      id: user.id,
      first_name: user.first_name,
      last_name: user.last_name,
      phone: user.phone,
      role: user.role,
      invite_code: user.invite_code,
      assignments: assignments,
      patrol_status: patrolStatus,
      ongoing_patrol: ongoingPatrol,
    };

    if (user.role === 'guard') {
      tokenPayload.assignments = assignments;
    }

    const token = generateToken(tokenPayload);

    // Create session with token so web views can call API
    req.session.user = {
      id: user.id,
      first_name: user.first_name,
      last_name: user.last_name,
      phone: user.phone,
      role: user.role,
      invite_code: user.invite_code,
      assignments: assignments,
      token: token,
    };

    // Get the returnTo URL from session or default to /admin/dashboard
    const returnTo = req.session.returnTo || '/admin/dashboard';
    delete req.session.returnTo; // Clear it after use

    res.json({
      message: 'Login successful',
      user: {
        id: user.id,
        first_name: user.first_name,
        last_name: user.last_name,
        phone: user.phone,
        role: user.role,
        invite_code: user.invite_code,
        assignments: assignments,
        patrol_status: patrolStatus,
        ongoing_patrol: ongoingPatrol,
      },
      token,
      patrol_status: patrolStatus,
      ongoing_patrol: ongoingPatrol,
      returnTo,
    });
  } catch (error) {
    console.error('Login Error:', error);
    res.status(500).json({ 
      error: 'Internal Server Error', 
      message: 'Failed to login' 
    });
  }
});

/**
 * POST /api/logout
 * Logout user and destroy session
 */
app.post('/api/logout', async (req, res) => {
  try {
    const authHeader = req.headers.authorization || '';
    const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
    const decoded = token ? verifyToken(token) : null;

    if (decoded?.id && decoded.role === 'guard') {
      const ongoingPatrol = await getLatestOngoingPatrol(decoded.id);
      if (ongoingPatrol && !ongoingPatrol.end_time) {
        return res.status(409).json({
          error: 'Active Patrol',
          code: 'ACTIVE_PATROL_LOGOUT_BLOCKED',
          message: 'You cannot logout while on patrol. End the patrol first.',
          patrol_status: normalizePatrolLifecycleStatus(ongoingPatrol.status),
          ongoing_patrol: ongoingPatrol,
        });
      }
    }

    req.session.destroy((err) => {
      if (err) {
        return res.status(500).json({
          error: 'Internal Server Error',
          message: 'Failed to logout',
        });
      }
      res.clearCookie('connect.sid');
      res.json({ message: 'Logout successful' });
    });
  } catch (error) {
    console.error('Logout error:', error);
    res.status(500).json({
      error: 'Internal Server Error',
      message: 'Failed to logout',
    });
  }
});

/**
 * GET /api/me
 * Get current user from session or JWT token
 */
app.get('/api/me', async (req, res) => {
  let currentUser = req.session?.user || null;

  if (!currentUser) {
    const authHeader = req.headers.authorization || '';
    const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
    if (token) {
      try {
        currentUser = verifyToken(token);
      } catch (tokenError) {
        console.error('Error verifying token for /api/me:', tokenError?.message || tokenError);
      }
    }
  }

  if (!currentUser) {
    return res.status(401).json({
      authenticated: false,
      message: 'Not authenticated',
    });
  }

  let company = '';
  let organization = null;

  try {
    if (currentUser.invite_code) {
      const orgResponse = await query(
        `/items/organizations?filter[invite_code][_eq]=${encodeURIComponent(currentUser.invite_code)}&fields=*&limit=1`
      );
      const org = (orgResponse.data.data || [])[0] || null;
      organization = org;
      company =
        org?.name ||
        org?.organization ||
        org?.organization_name ||
        org?.company_name ||
        org?.company ||
        org?.title ||
        org?.label ||
        org?.invite_code ||
        currentUser.invite_code ||
        '';
    }
  } catch (orgError) {
    console.error('Error fetching organization for /api/me:', orgError);
  }

  res.json({
    authenticated: true,
    user: {
      ...currentUser,
      company,
      organization,
    },
  });
});

/**
 * POST /api/admin/push-token
 * Register or update Expo push token for admin/supervisor notifications.
 * Body: { expo_push_token, platform? }
 */
app.post('/api/admin/push-token', verifyTokenMiddleware, async (req, res) => {
  try {
    const { expo_push_token, platform } = req.body || {};
    const { id, role, invite_code } = req.user || {};

    if (role !== 'admin' && role !== 'supervisor') {
      return res.status(403).json({
        error: 'Forbidden',
        message: 'Only admin or supervisor users can register push tokens',
      });
    }

    if (!invite_code) {
      return res.status(400).json({
        error: 'Bad Request',
        message: 'Missing organization invite code',
      });
    }

    const isExpoToken =
      typeof expo_push_token === 'string' &&
      (expo_push_token.startsWith('ExponentPushToken[') || expo_push_token.startsWith('ExpoPushToken['));
    if (!isExpoToken) {
      return res.status(400).json({
        error: 'Validation Error',
        message: 'A valid Expo push token is required',
      });
    }

    await upsertAdminPushToken({
      userId: id,
      inviteCode: invite_code,
      expoPushToken: expo_push_token,
      platform,
    });

    return res.json({
      message: 'Push token registered successfully',
    });
  } catch (error) {
    console.error('Error registering admin push token:', error);
    return res.status(500).json({
      error: 'Internal Server Error',
      message: 'Failed to register push token',
    });
  }
});

/**
 * DELETE /api/admin/push-token
 * Remove stored push token for current admin/supervisor device.
 */
app.delete('/api/admin/push-token', verifyTokenMiddleware, async (req, res) => {
  try {
    const { id, role } = req.user || {};

    if (role !== 'admin' && role !== 'supervisor') {
      return res.status(403).json({
        error: 'Forbidden',
        message: 'Only admin or supervisor users can remove push tokens',
      });
    }

    await deleteAdminPushToken({ userId: id });
    return res.json({ message: 'Push token removed successfully' });
  } catch (error) {
    console.error('Error removing admin push token:', error);
    return res.status(500).json({
      error: 'Internal Server Error',
      message: 'Failed to remove push token',
    });
  }
});

/**
 * POST /api/verify-token
 * Verify JWT token
 * Body: { token }
 */
app.post('/api/verify-token', (req, res) => {
  const { token } = req.body || {};
  
  if (!token) {
    return res.status(400).json({ 
      valid: false, 
      message: 'No token provided' 
    });
  }
  
  const decoded = verifyToken(token);
  
  if (decoded) {
    res.json({ valid: true, user: decoded });
  } else {
    res.status(401).json({ 
      valid: false, 
      message: 'Invalid or expired token' 
    });
  }
});

// ============================================
// ADMIN DASHBOARD — SUBSCRIPTION & PAYMENTS
// ============================================

/**
 * GET /admin/dashboard
 * Web-based admin dashboard page (session auth)
 */
app.get('/admin/dashboard', requireAuth, async (req, res) => {
  res.render('admin_dashboard', {
    user: req.session.user,
  });
});

/**
 * GET /api/admin/dashboard
 * Dashboard summary as JSON (token auth, used by mobile/api)
 * Optional ?org_id=xxx to scope data to a single organization
 */
app.get('/api/admin/dashboard', verifyTokenMiddleware, async (req, res) => {
  try {
    const orgId = req.query.org_id || null;
    const data = await buildDashboardSummary(orgId);
    res.json(data);
  } catch (err) {
    console.error('Dashboard error:', err);
    res.status(500).json({ error: 'Failed to load dashboard' });
  }
});

/**
 * GET /api/admin/dashboard/payments/:orgId
 * Payment history for a specific organization
 */
app.get('/api/admin/dashboard/payments/:orgId', verifyTokenMiddleware, async (req, res) => {
  try {
    const { orgId } = req.params;
    const result = await pool.query(
      'SELECT * FROM subscription_payments WHERE organization = $1 ORDER BY period_start DESC LIMIT 12',
      [orgId]
    );
    res.json({ payments: result.rows || [] });
  } catch (err) {
    console.error('Payments fetch error:', err);
    res.status(500).json({ error: 'Failed to fetch payments' });
  }
});

/**
 * POST /api/admin/dashboard/payments/:id/mark-paid
 * Mark a subscription payment as paid (uses pool.query to bypass Directus permission limits)
 */
app.post('/api/admin/dashboard/payments/:id/mark-paid', verifyTokenMiddleware, async (req, res) => {
  try {
    const paymentId = req.params.id;
    const { amount_paid, paid_at, payment_method } = req.body || {};

    await pool.query(
      `UPDATE subscription_payments SET status = 'paid', amount_paid = $1, paid_at = $2, payment_method = COALESCE($3, payment_method) WHERE id = $4`,
      [amount_paid || 0, paid_at || new Date().toISOString(), payment_method || null, paymentId]
    );

    res.json({ success: true, message: 'Payment marked as paid' });
  } catch (err) {
    console.error('Mark paid error:', err);
    res.status(500).json({ error: 'Failed to mark payment as paid' });
  }
});

/**
 * POST /api/admin/dashboard/organizations/:id/generate-payments
 * Auto-generate missing monthly payment records for an organization
 */
app.post('/api/admin/dashboard/organizations/:id/generate-payments', verifyTokenMiddleware, async (req, res) => {
  try {
    const orgId = req.params.id;
    const orgResult = await pool.query('SELECT * FROM organizations WHERE id = $1', [orgId]);
    const org = orgResult.rows[0];
    if (!org) return res.status(404).json({ error: 'Organization not found' });

    const existingResult = await pool.query(
      'SELECT DISTINCT TO_CHAR(period_start, \'YYYY-MM\') AS month_key FROM subscription_payments WHERE organization = $1',
      [orgId]
    );
    const existingMonths = new Set(existingResult.rows.map(r => r.month_key));

    const now = new Date();
    const generated = [];

    for (let i = 0; i >= -5; i--) {
      const d = new Date(now.getFullYear(), now.getMonth() + i, 1);
      const monthKey = `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}`;
      if (existingMonths.has(monthKey)) continue;

      const periodEnd = new Date(d.getFullYear(), d.getMonth() + 1, 0);
      const dueDate = new Date(d.getFullYear(), d.getMonth() + 1, 15);

      const insertResult = await pool.query(
        `INSERT INTO subscription_payments (organization, period_start, period_end, amount_due, amount_paid, status, due_date)
         VALUES ($1, $2, $3, $4, 0, 'unpaid', $5)
         RETURNING *`,
        [
          orgId,
          `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-01`,
          `${periodEnd.getFullYear()}-${String(periodEnd.getMonth() + 1).padStart(2, '0')}-${String(periodEnd.getDate()).padStart(2, '0')}`,
          org.monthly_rate || 0,
          `${dueDate.getFullYear()}-${String(dueDate.getMonth() + 1).padStart(2, '0')}-${String(dueDate.getDate()).padStart(2, '0')}`,
        ]
      );
      generated.push(insertResult.rows[0]);
    }

    res.json({ message: `Generated ${generated.length} pending payment records`, generated });
  } catch (err) {
    console.error('Generate payments error:', err);
    res.status(500).json({ error: 'Failed to generate payments' });
  }
});

/**
 * POST /api/admin/dashboard/generate-all-payments
 * Generate missing payment records for ALL organizations (batch)
 */
app.post('/api/admin/dashboard/generate-all-payments', verifyTokenMiddleware, async (req, res) => {
  try {
    const orgsResult = await pool.query('SELECT * FROM organizations');
    const orgs = orgsResult.rows || [];
    const results = [];
    const now = new Date();

    for (const org of orgs) {
      const existingResult = await pool.query(
        'SELECT DISTINCT TO_CHAR(period_start, \'YYYY-MM\') AS month_key FROM subscription_payments WHERE organization = $1',
        [org.id]
      );
      const existingMonths = new Set(existingResult.rows.map(r => r.month_key));
      let generated = 0;

      for (let i = 0; i >= -5; i--) {
        const d = new Date(now.getFullYear(), now.getMonth() + i, 1);
        const monthKey = `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}`;
        if (existingMonths.has(monthKey)) continue;

        const periodEnd = new Date(d.getFullYear(), d.getMonth() + 1, 0);
        const dueDate = new Date(d.getFullYear(), d.getMonth() + 1, 15);

        await pool.query(
          `INSERT INTO subscription_payments (organization, period_start, period_end, amount_due, amount_paid, status, due_date)
           VALUES ($1, $2, $3, $4, 0, 'unpaid', $5)`,
          [
            org.id,
            `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-01`,
            `${periodEnd.getFullYear()}-${String(periodEnd.getMonth() + 1).padStart(2, '0')}-${String(periodEnd.getDate()).padStart(2, '0')}`,
            org.monthly_rate || 0,
            `${dueDate.getFullYear()}-${String(dueDate.getMonth() + 1).padStart(2, '0')}-${String(dueDate.getDate()).padStart(2, '0')}`,
          ]
        );
        generated++;
      }
      if (generated > 0) results.push({ org: org.name, id: org.id, generated });
    }

    res.json({ message: `Generated payments for ${results.length} organizations`, details: results });
  } catch (err) {
    console.error('Batch generate error:', err);
    res.status(500).json({ error: 'Failed to generate payments' });
  }
});

/**
 * GET /api/admin/dashboard/guards
 * List all guards with contact info, assignments, and patrol status
 * Optional ?org_id=xxx to scope to a single organization (by invite_code)
 */
app.get('/api/admin/dashboard/guards', verifyTokenMiddleware, async (req, res) => {
  try {
    const orgId = req.query.org_id || null;
    let inviteCode = null;
    if (orgId) {
      const orgResult = await pool.query('SELECT invite_code FROM organizations WHERE id = $1', [orgId]);
      inviteCode = orgResult.rows[0]?.invite_code || null;
    }

    let guardsEndpoint = "/items/users?filter[role][_eq]=guard&fields=*";
    if (inviteCode) {
      guardsEndpoint += `&filter[invite_code][_eq]=${encodeURIComponent(inviteCode)}`;
    }
    const guardsResponse = await query(guardsEndpoint);
    const guards = guardsResponse.data.data || [];

    const locationsResponse = await query('/items/locations?fields=id,name');
    const locations = locationsResponse.data.data || [];
    const locationsById = new Map(locations.map(l => [l.id, l.name]));

    const enriched = [];
    for (const g of guards) {
      let assignment = null;
      let patrol = null;
      try {
        const a = await query(`/items/assignments?filter[user_id][_eq]=${g.id}&sort=-date_updated&limit=1`);
        assignment = (a.data.data || [])[0] || null;
      } catch (e) {}
      try {
        const p = await query(`/items/patrols?filter[user_id][_eq]=${g.id}&sort=-start_time&limit=1`);
        patrol = (p.data.data || [])[0] || null;
      } catch (e) {}

      const locId = assignment?.location || '';
      enriched.push({
        id: g.id,
        first_name: g.first_name,
        last_name: g.last_name,
        phone: g.phone,
        email: g.email,
        invite_code: g.invite_code,
        location: locationsById.get(locId) || locId || 'Not assigned',
        assigned_areas: assignment?.assigned_areas || '',
        operating_hours: assignment?.start_time && assignment?.end_time
          ? `${assignment.start_time} - ${assignment.end_time}`
          : 'Not set',
        patrol_status: patrol && !patrol.end_time ? 'On Patrol' : 'Inactive',
        last_access: g.last_access || null,
        status: g.status || 'active',
      });
    }
    res.json({ guards: enriched });
  } catch (err) {
    console.error('Guards fetch error:', err);
    res.status(500).json({ error: 'Failed to fetch guards' });
  }
});

/**
 * GET /api/admin/dashboard/supervisors
 * List all supervisors with masked phone (toggleable)
 * Optional ?org_id=xxx to scope to a single organization (by invite_code)
 */
app.get('/api/admin/dashboard/supervisors', verifyTokenMiddleware, async (req, res) => {
  try {
    const orgId = req.query.org_id || null;
    let inviteCode = null;
    if (orgId) {
      const orgResult = await pool.query('SELECT invite_code FROM organizations WHERE id = $1', [orgId]);
      inviteCode = orgResult.rows[0]?.invite_code || null;
    }

    let endpoint = "/items/users?filter[role][_eq]=supervisor&fields=*";
    if (inviteCode) {
      endpoint += `&filter[invite_code][_eq]=${encodeURIComponent(inviteCode)}`;
    }
    const response = await query(endpoint);
    const supervisors = (response.data.data || []).map(s => ({
      id: s.id,
      first_name: s.first_name,
      last_name: s.last_name,
      phone: s.phone ? s.phone.replace(/(\d{3})\d{4}(\d{2})/, '$1****$2') : null,
      phone_raw: s.phone || null,
      email: s.email,
      invite_code: s.invite_code,
      status: s.status || 'active',
      last_access: s.last_access || null,
    }));
    res.json({ supervisors });
  } catch (err) {
    console.error('Supervisors fetch error:', err);
    res.status(500).json({ error: 'Failed to fetch supervisors' });
  }
});

/**
 * GET /api/admin/dashboard/search?q=<query>
 * Search organizations by name
 */
app.get('/api/admin/dashboard/search', verifyTokenMiddleware, async (req, res) => {
  try {
    const q = (req.query.q || '').trim();
    if (!q) return res.json({ organizations: [] });

    const result = await pool.query(
      'SELECT id, name, invite_code, subscription_tier, subscription_status FROM organizations WHERE name ILIKE $1 LIMIT 20',
      [`%${q}%`]
    );
    res.json({ organizations: result.rows || [] });
  } catch (err) {
    console.error('Search error:', err);
    res.status(500).json({ error: 'Search failed' });
  }
});

/**
 * GET /api/admin/dashboard/organizations
 * List all organizations (for sidebar/search dropdown)
 */
app.get('/api/admin/dashboard/organizations', verifyTokenMiddleware, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id, name, invite_code, subscription_tier, subscription_status, monthly_rate FROM organizations ORDER BY name'
    );
    res.json({ organizations: result.rows || [] });
  } catch (err) {
    console.error('Orgs fetch error:', err);
    res.status(500).json({ error: 'Failed to fetch organizations' });
  }
});

/**
 * Build dashboard summary data (shared between API and web view)
 * Uses pool.query for subscription_payments (bypasses Directus static token permission limit)
 * @param {string|null} orgId - If provided, scope data to a single organization
 */
async function buildDashboardSummary(orgId = null) {
  let orgs = [];
  if (orgId) {
    const orgResult = await pool.query('SELECT * FROM organizations WHERE id = $1', [orgId]);
    if (orgResult.rows[0]) orgs = [orgResult.rows[0]];
  } else {
    const orgsResponse = await query('/items/organizations');
    orgs = orgsResponse.data.data || [];
  }

  let unpaidPayments = [];
  let recentPayments = [];
  try {
    let unpaidSql = "SELECT * FROM subscription_payments WHERE status IN ('unpaid', 'overdue')";
    let recentSql = 'SELECT * FROM subscription_payments';
    const params = [];
    if (orgId) {
      unpaidSql += ' AND organization = $1';
      recentSql += ' WHERE organization = $1';
      params.push(orgId);
    }
    recentSql += ' ORDER BY period_start DESC LIMIT 50';

    const unpaidResult = await pool.query(unpaidSql, params);
    unpaidPayments = unpaidResult.rows || [];

    const recentResult = await pool.query(recentSql, params);
    recentPayments = (recentResult.rows || []).map(p => ({
      id: p.id,
      organization: p.organization,
      period_start: p.period_start,
      period_end: p.period_end,
      amount_due: parseFloat(p.amount_due || 0).toFixed(2),
      amount_paid: parseFloat(p.amount_paid || 0).toFixed(2),
      status: p.status,
      due_date: p.due_date,
      paid_at: p.paid_at,
      payment_method: p.payment_method,
    }));
  } catch (e) {
    console.error('Error fetching subscription_payments:', e.message);
  }

  const totalOrgs = orgs.length;
  const activeSubscriptions = orgs.filter(o =>
    o.subscription_tier && o.subscription_tier !== 'free' && o.subscription_status === 'active'
  ).length;

  const totalOutstanding = unpaidPayments.reduce(
    (sum, p) => sum + parseFloat(p.amount_due || 0) - parseFloat(p.amount_paid || 0), 0
  );
  const overdueCount = unpaidPayments.filter(p => p.status === 'overdue').length;

  const monthlyRecurringRevenue = orgs
    .filter(o => o.subscription_status === 'active')
    .reduce((sum, o) => sum + parseFloat(o.monthly_rate || 0), 0);

  const tierBreakdown = {};
  for (const tier of ['free', 'basic', 'premium', 'enterprise']) {
    tierBreakdown[tier] = orgs.filter(o => (o.subscription_tier || 'free') === tier).length;
  }

  let totalGuards = 0;
  let supervisorCount = 0;
  try {
    let guardEndpoint = "/items/users?filter[role][_eq]=guard&aggregate[count]=id";
    if (orgId && orgs.length) {
      guardEndpoint += `&filter[invite_code][_eq]=${encodeURIComponent(orgs[0].invite_code)}`;
    }
    const guardsResponse = await query(guardEndpoint);
    totalGuards = guardsResponse.data.data?.[0]?.count?.id || 0;
  } catch (e) { /* ignore */ }
  try {
    let supEndpoint = "/items/users?filter[role][_eq]=supervisor&aggregate[count]=id";
    if (orgId && orgs.length) {
      supEndpoint += `&filter[invite_code][_eq]=${encodeURIComponent(orgs[0].invite_code)}`;
    }
    const supResponse = await query(supEndpoint);
    supervisorCount = supResponse.data.data?.[0]?.count?.id || 0;
  } catch (e) { /* ignore */ }

  const atRiskOrgs = orgs
    .filter(o => o.subscription_status === 'past_due')
    .map(o => ({ id: o.id, name: o.name, tier: o.subscription_tier }));

  const selectedOrg = orgs.length === 1 ? {
    id: orgs[0].id,
    name: orgs[0].name,
    invite_code: orgs[0].invite_code,
    subscription_tier: orgs[0].subscription_tier,
    subscription_status: orgs[0].subscription_status,
    monthly_rate: orgs[0].monthly_rate,
    max_guards: orgs[0].max_guards,
  } : null;

  return {
    total_organizations: totalOrgs,
    total_guards: totalGuards,
    supervisor_count: supervisorCount,
    active_subscriptions: activeSubscriptions,
    total_outstanding: totalOutstanding,
    overdue_payments: overdueCount,
    mrr: monthlyRecurringRevenue,
    tier_breakdown: tierBreakdown,
    at_risk_orgs: atRiskOrgs,
    recent_payments: recentPayments,
    selected_org: selectedOrg,
  };
}

// ============================================
// VIEW ROUTES
// ============================================

app.get('/', (req, res) => {
  res.render('index');
});

app.get('/login', (req, res) => {
  res.render('login');
});

app.get('/signup', (req, res) => {
  res.render('signup');
});

app.get('/paywall', (req, res) => {
  res.render('paywall');
});

app.get('/documentation', (req, res) => {
  res.render('documentation');
});

app.get('/api-endpoints', (req, res) => {
  res.render('api_endpoints');
});

app.get('/privacy-policy', (req, res) => {
  res.render('privacy_policy');
});

app.get('/delete-data', (req, res) => {
  res.render('delete_data');
});

app.get('/terms-of-service', (req, res) => {
  res.render('terms_of_service');
});

// ============================================
// ERROR HANDLING
// ============================================
app.use((err, req, res, next) => {
  console.error('Unhandled Error:', err);
  res.status(500).json({ 
    error: 'Internal Server Error', 
    message: 'An unexpected error occurred' 
  });
});

// ============================================
// GET ORGANIZATIONS INVITE CODES
// ============================================
app.get('/api/organizations/invite-codes', verifyTokenMiddleware, async (req, res) => {
  try {
    const response = await query('/items/organizations?fields=invite_code');
    const inviteCodes = response.data.data.map(org => org.invite_code);
    res.json({ inviteCodes });
  } catch (error) {
    console.error('Error fetching invite codes:', error);
    res.status(500).json({ 
      error: 'Internal Server Error', 
      message: 'Failed to fetch invite codes' 
    });
  }
});

// ============================================
// VALIDATE INVITE CODE (PUBLIC)
// ============================================
app.post('/api/organizations/validate-invite-code', loginLimiter, async (req, res) => {
  try {
    const { inviteCode } = req.body || {};

    if (!inviteCode || inviteCode.trim() === '') {
      return res.status(400).json({
        valid: false,
        message: 'Invite code is required'
      });
    }

    // Fetch all invite codes from organizations
    const response = await query('/items/organizations?fields=invite_code');
    const inviteCodes = response.data.data.map(org => org.invite_code);

    // Check if the provided code exists
    if (inviteCodes.includes(inviteCode)) {
      res.json({
        valid: true,
        message: 'Invite code is valid'
      });
    } else {
      res.status(404).json({
        valid: false,
        message: 'The organization is not registered with PatrolLink. Please check the code and try again, or contact your administrator.'
      });
    }
  } catch (error) {
    console.error('Error validating invite code:', error);
    res.status(500).json({
      valid: false,
      message: 'Failed to validate invite code'
    });
  }
});

// ============================================
// PATROLS ROUTES
// ============================================

/**
 * GET /api/patrols
 * Get all patrols for the logged-in guard
 * Query params: limit (optional), sort (optional)
 */
app.get('/api/patrols', verifyTokenMiddleware, async (req, res) => {
  try {
    const userId = req.user.id;
    const limit = sanitizeLimit(req.query.limit, 10);
    const sort = sanitizeSort(req.query.sort, '-start_time');

    // Fetch patrols for this guard from Directus
    const response = await query(`/items/patrols?filter[user_id][_eq]=${userId}&sort=${sort}&limit=${limit}`);
    const patrols = response.data.data || [];

    // Enrich patrols with GPS points from the high-scale table
    const patrolIds = patrols.map(p => p.id);
    let pointsByPatrol = {};
    if (patrolIds.length > 0) {
      try {
        const pointsResult = await pool.query(
          'SELECT patrol_id, latitude, longitude, timestamp FROM gps_points WHERE patrol_id = ANY($1) ORDER BY timestamp ASC',
          [patrolIds]
        );
        pointsByPatrol = pointsResult.rows.reduce((acc, point) => {
          if (!acc[point.patrol_id]) acc[point.patrol_id] = [];
          acc[point.patrol_id].push({
            latitude: point.latitude,
            longitude: point.longitude,
            timestamp: point.timestamp
          });
          return acc;
        }, {});
      } catch (pointsError) {
        console.error('Error fetching GPS points for enrichment:', pointsError);
      }
    }

    res.json({
      patrols: patrols.map((patrol) => ({
        ...patrol,
        map: pointsByPatrol[patrol.id] || patrol.map || [],
        status: normalizePatrolLifecycleStatus(patrol.status),
      })),
    });
  } catch (error) {
    console.error('Error fetching patrols:', error);
    res.status(500).json({
      error: 'Internal Server Error',
      message: 'Failed to fetch patrols'
    });
  }
});

/**
 * GET /api/admin/guards
 * Get all guards for the admin's organization
 * Requires authentication and returns guards with matching invite_code
 */
app.get('/api/admin/guards', verifyTokenMiddleware, async (req, res) => {
  try {
    const inviteCode = req.user.invite_code;

    // console.log('Invite code', inviteCode)

    if (!inviteCode) {
      return res.status(400).json({
        error: 'Bad Request',
        message: 'No organization invite code found'
      });
    }

    // Fetch users with role='guard' and matching invite_code
    const response = await query(`/items/users?filter[role][_eq]=guard&filter[invite_code][_eq]=${inviteCode}`);
    const guards = response.data.data || [];

    if (!guards.length) {
      return res.json({ guards: [] });
    }

    const guardIds = guards.map(g => g.id);

    // Load organization locations once so assignment.location IDs can be resolved to names.
    const locationsResponse = await query(`/items/locations?filter[organization][_eq]=${inviteCode}&fields=id,name`);
    const locations = locationsResponse.data.data || [];
    const locationsById = new Map();
    for (const loc of locations) {
      locationsById.set(loc.id, loc.name);
    }

    // Batch-fetch latest assignment per guard and latest patrol per guard
    let assignmentsByUser = {};
    let patrolsByUser = {};
    try {
      const assignResult = await pool.query(`
        SELECT DISTINCT ON (user_id) * FROM assignments
        WHERE user_id = ANY($1)
        ORDER BY user_id, date_updated DESC
      `, [guardIds]);
      for (const row of assignResult.rows) {
        assignmentsByUser[row.user_id] = row;
      }
    } catch (e) {
      console.error('Error batch-fetching assignments:', e.message);
    }
    try {
      const patrolResult = await pool.query(`
        SELECT DISTINCT ON (user_id) * FROM patrols
        WHERE user_id = ANY($1)
        ORDER BY user_id, start_time DESC
      `, [guardIds]);
      for (const row of patrolResult.rows) {
        patrolsByUser[row.user_id] = row;
      }
    } catch (e) {
      console.error('Error batch-fetching patrols:', e.message);
    }

    // Enrich guards with assignment and patrol data
    const enrichedGuards = guards.map(guard => {
      const assignment = assignmentsByUser[guard.id] || null;
      const latestPatrol = patrolsByUser[guard.id] || null;

      const locationId = assignment?.location || '';
      const locationName = locationId ? (locationsById.get(locationId) || locationId) : 'Not assigned';
      const normalizedPatrolStatus = latestPatrol
        ? normalizePatrolLifecycleStatus(latestPatrol.status)
        : PATROL_STATUS.INACTIVE_NOT_STARTED;
      const isOnActivePatrol =
        latestPatrol &&
        !latestPatrol.end_time &&
        normalizedPatrolStatus === PATROL_STATUS.ACTIVE_ON_PATROL;
      const isLoggedOutOnPatrol =
        latestPatrol &&
        !latestPatrol.end_time &&
        normalizedPatrolStatus === PATROL_STATUS.LOGGED_OUT_ON_PATROL;

      let lastSeen = guard.last_access || null;
      let lastSeenDisplay = 'Never';
      if (isOnActivePatrol) {
        lastSeenDisplay = 'Online (Currently on patrol)';
      } else if (isLoggedOutOnPatrol) {
        lastSeenDisplay = 'Logged out (Patrol ongoing)';
      } else if (latestPatrol?.end_time) {
        lastSeen = latestPatrol.end_time;
        lastSeenDisplay = latestPatrol.end_time;
      } else if (guard.last_access) {
        lastSeenDisplay = guard.last_access;
      }

      return {
        ...guard,
        location: locationName,
        location_id: locationId,
        assigned_areas: assignment?.assigned_areas || '',
        operating_hours_start: assignment?.start_time || '',
        operating_hours_end: assignment?.end_time || '',
        last_seen: lastSeen,
        last_seen_display: lastSeenDisplay,
        is_online: Boolean(isOnActivePatrol),
        patrol_status: normalizedPatrolStatus,
      };
    });

    res.json({
      guards: enrichedGuards
    });
  } catch (error) {
    console.error('Error fetching guards:', error);
    res.status(500).json({
      error: 'Internal Server Error',
      message: 'Failed to fetch guards'
    });
  }
});

/**
 * POST /api/admin/assignments
 * Create a new assignment for a guard in the admin's organization
 * Body: { user_id, location, assigned_areas, start_time, end_time }
 */
app.post('/api/admin/assignments', verifyTokenMiddleware, async (req, res) => {
  try {
    const inviteCode = req.user.invite_code;
    const { user_id, location, assigned_areas, start_time, end_time } = req.body || {};

    if (!inviteCode) {
      return res.status(400).json({
        error: 'Bad Request',
        message: 'No organization invite code found',
      });
    }

    if (!user_id || !location || !assigned_areas || !start_time || !end_time) {
      return res.status(400).json({
        error: 'Validation Error',
        message: 'user_id, location, assigned_areas, start_time, and end_time are required',
      });
    }

    const guardResponse = await query(
      `/items/users?filter[id][_eq]=${encodeURIComponent(user_id)}&filter[role][_eq]=guard&filter[invite_code][_eq]=${encodeURIComponent(inviteCode)}&limit=1`
    );
    const guard = (guardResponse.data.data || [])[0];
    if (!guard) {
      return res.status(404).json({
        error: 'Not Found',
        message: 'Guard not found in your organization',
      });
    }

    const locationResponse = await query(
      `/items/locations?filter[id][_eq]=${encodeURIComponent(location)}&filter[organization][_eq]=${encodeURIComponent(inviteCode)}&limit=1`
    );
    const organizationLocation = (locationResponse.data.data || [])[0];
    if (!organizationLocation) {
      return res.status(404).json({
        error: 'Not Found',
        message: 'Location not found in your organization',
      });
    }

    const assignmentData = {
      user_id: String(user_id).trim(),
      location: String(location).trim(),
      assigned_areas: String(assigned_areas).trim(),
      start_time: String(start_time).trim(),
      end_time: String(end_time).trim(),
      date_updated: new Date().toISOString(),
    };

    const response = await query('/items/assignments', {
      method: 'POST',
      data: assignmentData,
    });

    res.status(201).json({
      message: 'Assignment created successfully',
      assignment: response.data.data,
    });
  } catch (error) {
    console.error('Error creating admin assignment:', error);
    const statusCode = error.response?.status || 500;
    res.status(statusCode).json({
      error: 'Internal Server Error',
      message: 'Failed to create assignment',
      details: error.response?.data || error.message,
    });
  }
});

/**
 * DELETE /api/admin/guards/:id
 * Remove a guard from the admin's organization and cascade-delete related data.
 */
app.delete('/api/admin/guards/:id', verifyTokenMiddleware, async (req, res) => {
  try {
    const inviteCode = req.user.invite_code;
    const { id } = req.params;

    if (!inviteCode) {
      return res.status(400).json({
        error: 'Bad Request',
        message: 'No organization invite code found',
      });
    }

    const guardResponse = await query(
      `/items/users?filter[id][_eq]=${encodeURIComponent(id)}&filter[role][_eq]=guard&filter[invite_code][_eq]=${encodeURIComponent(inviteCode)}&limit=1`
    );
    const guard = (guardResponse.data.data || [])[0];
    if (!guard) {
      return res.status(404).json({
        error: 'Not Found',
        message: 'Guard not found in your organization',
      });
    }

    const deleteRelatedRecords = async (collection) => {
      const listResponse = await query(
        `/items/${collection}?filter[user_id][_eq]=${encodeURIComponent(id)}&fields=id&limit=-1`
      );
      const items = listResponse.data.data || [];
      for (const item of items) {
        await query(`/items/${collection}/${encodeURIComponent(item.id)}`, {
          method: 'DELETE',
        });
      }
      return items.length;
    };

    const deletedAssignments = await deleteRelatedRecords('assignments');
    const deletedLogs = await deleteRelatedRecords('logs');

    try {
      const patrolListResponse = await query(
        `/items/patrols?filter[user_id][_eq]=${encodeURIComponent(id)}&fields=id&limit=-1`
      );
      const patrolIds = (patrolListResponse.data.data || []).map(p => p.id);
      if (patrolIds.length > 0) {
        await pool.query('DELETE FROM gps_points WHERE patrol_id = ANY($1::varchar[])', [patrolIds]);
      }
    } catch (gpsError) {
      console.error(`Error deleting GPS points for guard ${id}:`, gpsError);
    }

    const deletedPatrols = await deleteRelatedRecords('patrols');

    await query(`/items/users/${encodeURIComponent(id)}`, {
      method: 'DELETE',
    });

    res.json({
      message: 'Guard removed successfully',
      deleted: {
        assignments: deletedAssignments,
        logs: deletedLogs,
        patrols: deletedPatrols,
      },
    });
  } catch (error) {
    console.error('Error deleting guard:', error);
    const statusCode = error.response?.status || 500;
    res.status(statusCode).json({
      error: 'Internal Server Error',
      message: 'Failed to remove guard',
      details: error.response?.data || error.message,
    });
  }
});

/**
 * GET /api/admin/patrols
 * Get all patrols for the admin's organization
 * Query params: limit (optional), sort (optional)
 */
app.get('/api/admin/patrols', verifyTokenMiddleware, async (req, res) => {
  try {
    const inviteCode = req.user.invite_code;
    const limit = sanitizeLimit(req.query.limit, 50);
    const sort = sanitizeSort(req.query.sort, '-start_time');

    // First get all guards for this organization
    const guardsResponse = await query(`/items/users?filter[role][_eq]=guard&filter[invite_code][_eq]=${inviteCode}&fields=id`);
    const guards = guardsResponse.data.data;

    if (!guards || guards.length === 0) {
      return res.json({ patrols: [] });
    }

    // Get guard IDs
    const guardIds = guards.map(g => g.id);

    // Fetch patrols for all guards in a single batch query
    let allPatrols = [];
    try {
      const patrolResult = await pool.query(
        'SELECT * FROM patrols WHERE user_id = ANY($1) ORDER BY start_time DESC',
        [guardIds]
      );
      allPatrols = patrolResult.rows || [];
    } catch (patrolError) {
      console.error('Error batch-fetching patrols:', patrolError);
    }

    // Sort combined patrols by start_time
    allPatrols.sort((a, b) => new Date(b.start_time) - new Date(a.start_time));

    // Limit results
    const limitedPatrols = allPatrols.slice(0, parseInt(limit));

    // Enrich patrols with GPS points from the new high-scale table
    const patrolIds = limitedPatrols.map(p => p.id);
    let pointsByPatrol = {};
    if (patrolIds.length > 0) {
      try {
        const pointsResult = await pool.query(
          'SELECT patrol_id, latitude, longitude, timestamp FROM gps_points WHERE patrol_id = ANY($1) ORDER BY timestamp ASC',
          [patrolIds]
        );
        pointsByPatrol = pointsResult.rows.reduce((acc, point) => {
          if (!acc[point.patrol_id]) acc[point.patrol_id] = [];
          acc[point.patrol_id].push({
            latitude: point.latitude,
            longitude: point.longitude,
            timestamp: point.timestamp
          });
          return acc;
        }, {});
      } catch (pointsError) {
        console.error('Error fetching GPS points for enrichment:', pointsError);
      }
    }

    // Build location lookup so assignment location IDs can be resolved to names.
    const locationsById = new Map();
    try {
      const locationsResponse = await query(`/items/locations?filter[organization][_eq]=${inviteCode}&fields=id,name`);
      const locations = locationsResponse.data.data || [];
      for (const location of locations) {
        locationsById.set(location.id, location.name);
      }
    } catch (locationError) {
      console.error('Error fetching locations for patrol enrichment:', locationError);
    }

    // Enrich each patrol using its user_id:
    // 1) fetch user -> guard_name
    // 2) fetch assignment by user_id -> assigned areas and assignment location
    const enrichedPatrols = [];
    for (const patrol of limitedPatrols) {
      const guardId = patrol.user_id;
      let guard = null;
      let assignment = null;

      try {
        const guardResponse = await query(`/items/users/${guardId}?fields=id,first_name,last_name`);
        guard = guardResponse?.data?.data || null;
      } catch (guardError) {
        console.error(`Error fetching guard ${guardId} for patrol ${patrol.id}:`, guardError);
      }

      try {
        const assignmentResponse = await query(
          `/items/assignments?filter[user_id][_eq]=${guardId}&sort=-date_updated&limit=1`
        );
        assignment = (assignmentResponse.data.data || [])[0] || null;
      } catch (assignmentError) {
        console.error(`Error fetching assignment for guard ${guardId}:`, assignmentError);
      }

      const resolvedLocationName = assignment?.location ? (locationsById.get(assignment.location) || assignment.location) : null;
      const guardName = guard ? `${guard.first_name || ''} ${guard.last_name || ''}`.trim() : '';
      const assignmentAreas = assignment?.assigned_areas || '';
      const assignmentCheckpoints = assignmentAreas
        ? assignmentAreas.split(',').map((area) => area.trim()).filter(Boolean)
        : [];

      enrichedPatrols.push({
        ...patrol,
        map: pointsByPatrol[patrol.id] || patrol.map || [],
        status: normalizePatrolLifecycleStatus(patrol.status),
        guard_name: guardName || patrol.guard_name || 'Unknown Guard',
        assigned_areas: assignmentAreas || patrol.assigned_areas || '',
        location: patrol.location || resolvedLocationName || 'Unknown Location',
        checkpoints: assignmentCheckpoints,
      });
    }

    res.json({
      patrols: enrichedPatrols
    });
  } catch (error) {
    console.error('Error fetching admin patrols:', error);
    res.status(500).json({
      error: 'Internal Server Error',
      message: 'Failed to fetch patrols'
    });
  }
});

/**
 * GET /api/admin/locations
 * Get all locations for the admin's organization
 */
app.get('/api/admin/locations', verifyTokenMiddleware, async (req, res) => {
  try {
    const inviteCode = req.user.invite_code;

    if (!inviteCode) {
      return res.status(400).json({
        error: 'Bad Request',
        message: 'No organization invite code found'
      });
    }

    // Fetch locations where organization matches invite_code
    const response = await query(`/items/locations?filter[organization][_eq]=${inviteCode}`);

    res.json({
      locations: response.data.data
    });
  } catch (error) {
    console.error('Error fetching locations:', error);
    res.status(500).json({
      error: 'Internal Server Error',
      message: 'Failed to fetch locations'
    });
  }
});

/**
 * POST /api/admin/locations
 * Create a location for the admin's organization
 * Body: { name, assigned_areas? }
 */
app.post('/api/admin/locations', verifyTokenMiddleware, async (req, res) => {
  try {
    const inviteCode = req.user.invite_code;
    const { name, assigned_areas } = req.body || {};

    if (!inviteCode) {
      return res.status(400).json({
        error: 'Bad Request',
        message: 'No organization invite code found',
      });
    }

    if (!name || !String(name).trim()) {
      return res.status(400).json({
        error: 'Validation Error',
        message: 'Location name is required',
      });
    }

    const locationData = {
      name: String(name).trim(),
      assigned_areas: assigned_areas ? String(assigned_areas).trim() : '',
      organization: inviteCode,
    };

    const response = await query('/items/locations', {
      method: 'POST',
      data: locationData,
    });

    res.status(201).json({
      message: 'Location created successfully',
      location: response.data.data,
    });
  } catch (error) {
    console.error('Error creating location:', error);
    const statusCode = error.response?.status || 500;
    res.status(statusCode).json({
      error: 'Internal Server Error',
      message: 'Failed to create location',
      details: error.response?.data || error.message,
    });
  }
});

/**
 * PATCH /api/admin/locations/:id
 * Update a location for the admin's organization
 * Body: { name?, assigned_areas? }
 */
app.patch('/api/admin/locations/:id', verifyTokenMiddleware, async (req, res) => {
  try {
    const inviteCode = req.user.invite_code;
    const { id } = req.params;
    const { name, assigned_areas } = req.body || {};

    if (!inviteCode) {
      return res.status(400).json({
        error: 'Bad Request',
        message: 'No organization invite code found',
      });
    }

    const existingResponse = await query(
      `/items/locations?filter[id][_eq]=${encodeURIComponent(id)}&filter[organization][_eq]=${encodeURIComponent(inviteCode)}&limit=1`
    );
    const existingLocation = (existingResponse.data.data || [])[0];
    if (!existingLocation) {
      return res.status(404).json({
        error: 'Not Found',
        message: 'Location not found',
      });
    }

    const updateData = {};
    if (name !== undefined) {
      if (!String(name).trim()) {
        return res.status(400).json({
          error: 'Validation Error',
          message: 'Location name cannot be empty',
        });
      }
      updateData.name = String(name).trim();
    }
    if (assigned_areas !== undefined) {
      updateData.assigned_areas = String(assigned_areas).trim();
    }

    if (Object.keys(updateData).length === 0) {
      return res.status(400).json({
        error: 'Validation Error',
        message: 'No fields provided to update',
      });
    }

    const response = await query(`/items/locations/${encodeURIComponent(id)}`, {
      method: 'PATCH',
      data: updateData,
    });

    res.json({
      message: 'Location updated successfully',
      location: response.data.data,
    });
  } catch (error) {
    console.error('Error updating location:', error);
    const statusCode = error.response?.status || 500;
    res.status(statusCode).json({
      error: 'Internal Server Error',
      message: 'Failed to update location',
      details: error.response?.data || error.message,
    });
  }
});

/**
 * DELETE /api/admin/locations/:id
 * Delete a location for the admin's organization
 */
app.delete('/api/admin/locations/:id', verifyTokenMiddleware, async (req, res) => {
  try {
    const inviteCode = req.user.invite_code;
    const { id } = req.params;

    if (!inviteCode) {
      return res.status(400).json({
        error: 'Bad Request',
        message: 'No organization invite code found',
      });
    }

    const existingResponse = await query(
      `/items/locations?filter[id][_eq]=${encodeURIComponent(id)}&filter[organization][_eq]=${encodeURIComponent(inviteCode)}&limit=1`
    );
    const existingLocation = (existingResponse.data.data || [])[0];
    if (!existingLocation) {
      return res.status(404).json({
        error: 'Not Found',
        message: 'Location not found',
      });
    }

    await query(`/items/locations/${encodeURIComponent(id)}`, {
      method: 'DELETE',
    });

    res.json({
      message: 'Location deleted successfully',
      id,
    });
  } catch (error) {
    console.error('Error deleting location:', error);
    const statusCode = error.response?.status || 500;
    res.status(statusCode).json({
      error: 'Internal Server Error',
      message: 'Failed to delete location',
      details: error.response?.data || error.message,
    });
  }
});

/**
 * Shared handler for admin logs endpoint.
 */
const getAdminLogsHandler = async (req, res) => {
  try {
    const inviteCode = req.user.invite_code;
    const limit = sanitizeLimit(req.query.limit, 50);
    const sort = sanitizeSort(req.query.sort, '-timestamp');

    // First get all guards for this organization
    const guardsResponse = await query(`/items/users?filter[role][_eq]=guard&filter[invite_code][_eq]=${inviteCode}&fields=id`);
    const guards = guardsResponse.data.data;

    if (!guards || guards.length === 0) {
      return res.json({ logs: [] });
    }

    // Get guard IDs
    const guardIds = guards.map(g => g.id);

    // Fetch logs for all guards in a single batch query
    let allLogs = [];
    try {
      const logResult = await pool.query(
        'SELECT * FROM logs WHERE user_id = ANY($1) ORDER BY timestamp DESC',
        [guardIds]
      );
      allLogs = logResult.rows || [];
    } catch (logError) {
      console.error('Error batch-fetching logs:', logError);
    }

    // Limit results
    const limitedLogs = allLogs.slice(0, parseInt(limit));

    // Resolve log location from user -> assignment -> location name.
    const locationsById = new Map();
    try {
      const locationsResponse = await query(`/items/locations?filter[organization][_eq]=${inviteCode}&fields=id,name`);
      const locations = locationsResponse.data.data || [];
      for (const location of locations) {
        locationsById.set(location.id, location.name);
      }
    } catch (locationError) {
      console.error('Error fetching locations for admin logs location mapping:', locationError);
    }

    // Batch-fetch latest assignment per guard
    const assignmentByUserId = new Map();
    try {
      const assignResult = await pool.query(`
        SELECT DISTINCT ON (user_id) * FROM assignments
        WHERE user_id = ANY($1)
        ORDER BY user_id, date_updated DESC
      `, [guardIds]);
      for (const row of assignResult.rows) {
        assignmentByUserId.set(row.user_id, row);
      }
    } catch (assignError) {
      console.error('Error batch-fetching assignments for logs:', assignError);
    }

    const logsWithResolvedLocation = limitedLogs.map((log) => {
      const assignment = assignmentByUserId.get(log.user_id);
      const resolvedLocation = assignment?.location
        ? (locationsById.get(assignment.location) || assignment.location)
        : null;

      return {
        ...log,
        location: log.location || resolvedLocation || 'Unknown Location',
      };
    });

    res.json({
      logs: logsWithResolvedLocation
    });
  } catch (error) {
    console.error('Error fetching admin logs:', error);
    res.status(500).json({
      error: 'Internal Server Error',
      message: 'Failed to fetch logs'
    });
  }
};

/**
 * GET /api/admin/logs
 * Get all logs for the admin's organization
 * Query params: limit (optional), sort (optional)
 */
app.get('/api/admin/logs', verifyTokenMiddleware, getAdminLogsHandler);

/**
 * GET /api/admin/notifications
 * Build admin notification feed from logs, assignments, and patrol state.
 * Query params: limit (optional)
 */
app.get('/api/admin/notifications', verifyTokenMiddleware, async (req, res) => {
  try {
    const inviteCode = req.user.invite_code;
    const limit = sanitizeLimit(req.query.limit, 100);

    if (!inviteCode) {
      return res.status(400).json({
        error: 'Bad Request',
        message: 'No organization invite code found',
      });
    }

    const notifications = await buildAdminNotifications(inviteCode, limit);
    return res.json({
      notifications,
      generated_at: new Date().toISOString(),
    });
  } catch (error) {
    console.error('Error building admin notifications:', error);
    return res.status(500).json({
      error: 'Internal Server Error',
      message: 'Failed to fetch admin notifications',
    });
  }
});

/**
 * Normalize map payloads before persisting.
 * Supports stringified JSON, arrays, and objects.
 */
const normalizeMapValue = (value) => {
  if (value === null || value === undefined) return null;
  if (typeof value === 'string') return value;
  try {
    return JSON.stringify(value);
  } catch (_error) {
    return null;
  }
};

/**
 * POST /api/patrols
 * Create a new patrol
 * Body: { start_time, user_id, organization_id, duration?, end_time?, map? }
 */
app.post('/api/patrols', verifyTokenMiddleware, async (req, res) => {
  try {
    const { start_time, user_id, organization_id, duration, end_time, map, location_data } = req.body || {};

    // Validate required fields
    if (!start_time || !user_id) {
      return res.status(400).json({
        error: 'Validation Error',
        message: 'start_time and user_id are required'
      });
    }

    // Create patrol in Directus
    const patrolData = {
      start_time,
      user_id,
      organization_id: organization_id || null,
      duration: typeof duration === 'number' ? duration : null,
      end_time: end_time || null,
      map: normalizeMapValue(map !== undefined ? map : location_data),
      status: PATROL_STATUS.ACTIVE_ON_PATROL,
    };

    const response = await query('/items/patrols', {
      method: 'POST',
      data: patrolData,
    });

    res.status(201).json({
      message: 'Patrol started successfully',
      data: response.data.data
    });
  } catch (error) {
    console.error('Error creating patrol:', error);
    res.status(500).json({
      error: 'Internal Server Error',
      message: 'Failed to create patrol'
    });
  }
});

/**
 * PATCH /api/patrols/:id
 * Update a patrol (e.g., end time, location data)
 * Body: { duration?, start_time?, end_time?, map?, location_data?, status? }
 */
app.patch('/api/patrols/:id', verifyTokenMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    // console.log("Param id:", id)
    const {
      duration,
      end_time,
      map,
      location_data,
      status
    } = req.body || {};

    let existingPatrol = null;
    try {
      const patrolResponse = await query(`/items/patrols/${encodeURIComponent(id)}`);
      existingPatrol = patrolResponse?.data?.data || null;
    } catch (fetchPatrolError) {
      console.error(`Error fetching patrol ${id} before update:`, fetchPatrolError);
    }

    // console.log("Data body:", req.body)

    // Build update data - use 'map' field as per Directus collection schema
    const updateData = {};
    
    if (typeof duration === 'number') {
      updateData.duration = duration;
    }
    if (end_time) {
      updateData.end_time = end_time;
    }
    if (map) {
      updateData.map = normalizeMapValue(map);
    } else if (location_data) {
      updateData.map = normalizeMapValue(location_data);
    }
    if (status) {
      updateData.status = normalizePatrolLifecycleStatus(status);
    }

    // If end_time is provided, mark patrol as completed.
    if (end_time && !status) {
      updateData.status = PATROL_STATUS.COMPLETED;
    }

    // If patrol is being ended, aggregate all points from gps_points and sync to 'map' field
    // for permanent record in Directus. This runs only once per patrol.
    if (updateData.status === PATROL_STATUS.COMPLETED || end_time) {
      try {
        const pointsResult = await pool.query(
          'SELECT latitude, longitude, timestamp FROM gps_points WHERE patrol_id = $1 ORDER BY timestamp ASC',
          [id]
        );
        if (pointsResult.rows.length > 0) {
          updateData.map = JSON.stringify(pointsResult.rows);
        }
      } catch (syncError) {
        console.error('Failed to sync GPS points to patrol map on completion:', syncError);
      }
    }

    // Update patrol in Directus. If duration is rejected by schema/permissions,
    // retry without duration so patrol completion still gets recorded.
    let response;
    try {
      response = await query(`/items/patrols/${id}`, {
        method: 'PATCH',
        data: updateData,
      });
    } catch (updateError) {
      const hasDuration = Object.prototype.hasOwnProperty.call(updateData, 'duration');
      if (!hasDuration) {
        throw updateError;
      }

      const fallbackData = { ...updateData };
      delete fallbackData.duration;

      response = await query(`/items/patrols/${id}`, {
        method: 'PATCH',
        data: fallbackData,
      });

      return res.json({
        message: 'Patrol updated, but duration was not persisted',
        warning: 'duration_not_saved',
        data: response.data.data,
        details: updateError.response?.data || updateError.message,
      });
    }

    res.json({
      message: 'Patrol updated successfully',
      data: response.data.data
    });

    const updatedPatrol = response?.data?.data || null;
    const normalizedNewStatus = normalizePatrolLifecycleStatus(
      status || updatedPatrol?.status || existingPatrol?.status
    );
    const guardId = updatedPatrol?.user_id || existingPatrol?.user_id || req.user?.id || null;

    if (normalizedNewStatus === PATROL_STATUS.LOGGED_OUT_ON_PATROL && updatedPatrol && !updatedPatrol.end_time && guardId) {
      try {
        const guardResponse = await query(`/items/users/${encodeURIComponent(guardId)}?fields=id,first_name,last_name,invite_code`);
        const guard = guardResponse?.data?.data || null;
        const inviteCode = guard?.invite_code || req.user?.invite_code;
        if (inviteCode) {
          await dispatchPushToOrganization({
            inviteCode,
            eventType: ADMIN_NOTIFICATION_TYPE.GUARD_LOGGED_OUT_ON_PATROL,
            eventKey: `${ADMIN_NOTIFICATION_TYPE.GUARD_LOGGED_OUT_ON_PATROL}:${updatedPatrol.id}`,
            title: `${getGuardDisplayName(guard)} logged out while on patrol`,
            body: 'Patrol remains open and is marked as logged out on patrol.',
            data: {
              type: ADMIN_NOTIFICATION_TYPE.GUARD_LOGGED_OUT_ON_PATROL,
              guard_id: guardId,
              guard_name: getGuardDisplayName(guard),
              patrol_id: updatedPatrol.id,
              location: updatedPatrol.location || 'Unknown Location',
            },
            priority: 'high',
          });
        }
      } catch (dispatchError) {
        console.error('Failed dispatching logged-out-on-patrol push notification:', dispatchError);
      }
    }

    if ((end_time || updatedPatrol?.end_time) && guardId) {
      try {
        const patrolEnd = safeDate(end_time || updatedPatrol?.end_time);
        const guardResponse = await query(`/items/users/${encodeURIComponent(guardId)}?fields=id,first_name,last_name,invite_code`);
        const guard = guardResponse?.data?.data || null;
        const inviteCode = guard?.invite_code || req.user?.invite_code;
        const assignment = await getLatestAssignmentForGuard(guardId);

        if (patrolEnd && assignment?.end_time && inviteCode) {
          const shiftEndForPatrolDate = parseShiftTimeOnReferenceDate(
            assignment.end_time,
            patrolEnd
          );
          if (shiftEndForPatrolDate && shiftEndForPatrolDate.getTime() - patrolEnd.getTime() > 60 * 1000) {
            await dispatchPushToOrganization({
              inviteCode,
              eventType: ADMIN_NOTIFICATION_TYPE.PATROL_ENDED_EARLY,
              eventKey: `${ADMIN_NOTIFICATION_TYPE.PATROL_ENDED_EARLY}:${updatedPatrol?.id || id}`,
              title: `${getGuardDisplayName(guard)} ended patrol early`,
              body: `Patrol ended before assigned end time (${assignment.end_time}).`,
              data: {
                type: ADMIN_NOTIFICATION_TYPE.PATROL_ENDED_EARLY,
                guard_id: guardId,
                guard_name: getGuardDisplayName(guard),
                patrol_id: updatedPatrol?.id || id,
                location: updatedPatrol?.location || existingPatrol?.location || 'Unknown Location',
              },
              priority: 'default',
            });
          }
        }
      } catch (dispatchError) {
        console.error('Failed dispatching early-ended patrol push notification:', dispatchError);
      }
    }
  } catch (error) {
    console.error('Error updating patrol:', error);
    const statusCode = error.response?.status || 500;
    res.status(statusCode).json({
      error: 'Internal Server Error',
      message: 'Failed to update patrol',
      details: error.response?.data || error.message
    });
  }
});

/**
 * PATCH /api/patrols/:id/location
 * Update patrol location incrementally by inserting new points into the gps_points table.
 * Body: { location_data: [{ latitude, longitude, timestamp }, ...] }
 */
app.patch('/api/patrols/:id/location', verifyTokenMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    const { location_data } = req.body || {};

    if (!location_data || !Array.isArray(location_data) || location_data.length === 0) {
      return res.status(400).json({
        error: 'Validation Error',
        message: 'location_data array is required and must not be empty'
      });
    }

    // Build values for multi-row insert
    const values = [];
    const params = [];
    let paramCounter = 1;

    location_data.forEach((point) => {
      const lat = parseFloat(point.latitude);
      const lng = parseFloat(point.longitude);
      const ts = point.timestamp || new Date().toISOString();

      if (!isNaN(lat) && !isNaN(lng)) {
        values.push(`($${paramCounter}, $${paramCounter + 1}, $${paramCounter + 2}, $${paramCounter + 3})`);
        params.push(id, lat, lng, ts);
        paramCounter += 4;
      }
    });

    if (values.length === 0) {
      return res.status(400).json({
        error: 'Validation Error',
        message: 'No valid coordinates found in location_data'
      });
    }

    const sql = `
      INSERT INTO gps_points (patrol_id, latitude, longitude, timestamp)
      VALUES ${values.join(', ')}
    `;

    await pool.query(sql, params);

    res.json({
      message: 'Location points recorded successfully',
      points_count: values.length
    });
  } catch (error) {
    console.error('Error recording patrol location:', error);
    res.status(500).json({
      error: 'Internal Server Error',
      message: 'Failed to record location data'
    });
  }
});

// ============================================
// LOGS ROUTES
// ============================================

/**
 * GET /api/logs
 * Get all logs for the logged-in guard
 * Query params: limit (optional), sort (optional)
 */
app.get('/api/logs', verifyTokenMiddleware, async (req, res) => {
  try {
    const userId = req.user.id;
    const limit = sanitizeLimit(req.query.limit, 50);
    const sort = sanitizeSort(req.query.sort, '-timestamp');

    // Fetch logs for this guard from Directus
    const response = await query(`/items/logs?filter[user_id][_eq]=${userId}&sort=${sort}&limit=${limit}`);

    res.json({
      logs: response.data.data
    });
  } catch (error) {
    console.error('Error fetching logs:', error);
    res.status(500).json({
      error: 'Internal Server Error',
      message: 'Failed to fetch logs'
    });
  }
});

/**
 * POST /api/logs
 * Create a new log entry
 * Body: { title, description, category, images?, patrol_id? }
 */
app.post('/api/logs', verifyTokenMiddleware, async (req, res) => {
  try {
    const userId = req.user.id;
    const inviteCode = req.user.invite_code;
    const { title, description, category, images, patrol_id } = req.body || {};

    // console.log("Body:", req.body)

    // Validate required fields
    if (!title || !description || !category) {
      return res.status(400).json({
        error: 'Validation Error',
        message: 'title, description, and category are required'
      });
    }

    // Validate category
    const validCategories = ['activity', 'unusual', 'incident', 'checkpoint', 'other'];
    if (!validCategories.includes(category)) {
      return res.status(400).json({
        error: 'Validation Error',
        message: 'category must be one of: activity, unusual, incident, checkpoint, other'
      });
    }

    // Create log in Directus
    const logData = {
      title,
      description,
      category,
      user_id: userId,
      patrol_id: patrol_id || null,
      images: images || null,
      timestamp: new Date().toISOString(),
    };

    const response = await query('/items/logs', {
      method: 'POST',
      data: logData,
    });

    res.status(201).json({
      message: 'Log created successfully',
      data: response.data.data
    });

    try {
      const guardName = `${req.user?.first_name || ''} ${req.user?.last_name || ''}`.trim() || 'Guard';
      await dispatchPushToOrganization({
        inviteCode,
        eventType: ADMIN_NOTIFICATION_TYPE.LOG_CREATED,
        eventKey: `${ADMIN_NOTIFICATION_TYPE.LOG_CREATED}:${response?.data?.data?.id || crypto.randomUUID()}`,
        title: `New log from ${guardName}`,
        body: `${title}: ${description}`,
        data: {
          type: ADMIN_NOTIFICATION_TYPE.LOG_CREATED,
          guard_id: userId,
          guard_name: guardName,
          patrol_id: patrol_id || null,
          log_id: response?.data?.data?.id || null,
          category,
        },
        priority: category === 'incident' ? 'high' : 'default',
      });
    } catch (pushError) {
      console.error('Failed dispatching new-log push notification:', pushError);
    }
  } catch (error) {
    console.error('Error creating log:', error);
    res.status(500).json({
      error: 'Internal Server Error',
      message: 'Failed to create log'
    });
  }
});

// ============================================
// Deleting user account
// ============================================
const deleteUserAccount = async (userId) => {
  try {
    const deleteRelatedRecords = async (collection) => {
      const listResponse = await query(
        `/items/${collection}?filter[user_id][_eq]=${encodeURIComponent(userId)}&fields=id&limit=-1`
      );
      const items = listResponse.data.data || [];
      for (const item of items) {
        await query(`/items/${collection}/${encodeURIComponent(item.id)}`, {
          method: 'DELETE',
        });
      }
      return items.length;
    };

    const deletedAssignments = await deleteRelatedRecords('assignments');
    const deletedLogs = await deleteRelatedRecords('logs');

    try {
      const patrolListResponse = await query(
        `/items/patrols?filter[user_id][_eq]=${encodeURIComponent(userId)}&fields=id&limit=-1`
      );
      const patrolIds = (patrolListResponse.data.data || []).map(p => p.id);
      if (patrolIds.length > 0) {
        await pool.query('DELETE FROM gps_points WHERE patrol_id = ANY($1::varchar[])', [patrolIds]);
      }
    } catch (gpsError) {
      console.error(`Error deleting GPS points for user ${userId}:`, gpsError);
    }

    const deletedPatrols = await deleteRelatedRecords('patrols');

    await query(`/items/users/${encodeURIComponent(userId)}`, {
      method: 'DELETE',
    });

    console.log(`User ${userId} and related records deleted successfully`);
  } catch (error) {
    console.error(`Error deleting user ${userId}:`, error);
  }
};

// Endpoint for users to delete their own account
app.delete('/api/account', verifyTokenMiddleware, async (req, res) => {
  try {
    const userId = req.user.id;
    await deleteUserAccount(userId);
    res.json({
      message: 'Your account and related data have been deleted successfully',
    });
  } catch (error) {
    console.error('Error deleting user account:', error);
    res.status(500).json({
      error: 'Internal Server Error',
      message: 'Failed to delete account',
    });
  }
});


// ============================================
// START SERVER
// ============================================
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`📱 PatrolLink API ready at http://localhost:${PORT}/api`);
  console.log(`📖 API Documentation at http://localhost:${PORT}/documentation`);

  setTimeout(() => {
    runPeriodicPushScan().catch((error) => {
      console.error('Initial periodic push scan failed:', error);
    });
  }, PERIODIC_PUSH_STARTUP_DELAY_MS);
  if (!periodicPushScanInterval) {
    periodicPushScanInterval = setInterval(() => {
      runPeriodicPushScan().catch((error) => {
        console.error('Scheduled periodic push scan failed:', error);
      });
    }, PERIODIC_PUSH_SCAN_MS);
  }
});

module.exports = app;
