/*
 * SPDX-FileCopyrightText: 2026 Famedly GmbH (info@famedly.com)
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/*
 * Knot DNS test module "mod-ignoreme": silently drops the updates (but not
 * the prerequisites) of RFC 2136 UPDATE messages whose owner name has the
 * leftmost label "ignore-me". The server still answers NOERROR, like a
 * server that acknowledges but ignores parts of an update. Used by the
 * end-to-end tests to check that a client does not trust its own idea of
 * the zone contents after such an update.
 *
 * TSIG: the rewritten message no longer matches the client's MAC. Knot
 * verifies the request with the parsed TSIG RR (query->tsig_rr), but
 * stores the raw TSIG bytes (query->tsig_wire) with the queued update,
 * and signs the deferred response with the MAC found there. So the module
 *   1. verifies the client's MAC itself (untouched if it does not match,
 *      so knot rejects the message as usual),
 *   2. rewrites the message body,
 *   3. puts the MAC of the rewritten body into the parsed TSIG RR, which
 *      makes knot's own verification (and ACL check) pass, and
 *   4. keeps the client's MAC in the raw TSIG bytes, so the response is
 *      signed with the client's request MAC and verifies on the client.
 * This relies on knot internals (checked against Knot DNS 3.5).
 *
 * Usage: module: - id: mod-ignoreme, file: /path/to/ignoreme.so
 *        template/zone: module: mod-ignoreme
 */

#include <string.h>
#include <strings.h>

#include <knot/module.h>
#include <libdnssec/error.h>
#include <libdnssec/tsig.h>

#define LABEL "ignore-me"

static bool is_ignored(const knot_dname_t *owner)
{
	return owner[0] == strlen(LABEL) &&
	       strncasecmp((const char *)owner + 1, LABEL, strlen(LABEL)) == 0;
}

static void put16(uint8_t *p, uint16_t v)
{
	p[0] = v >> 8;
	p[1] = v & 0xff;
}

/* MAC of a request (RFC 8945 Section 4.3.3) over `msg` (without TSIG). */
static int request_mac(const knot_rrset_t *tsig, const uint8_t *msg, size_t len,
                       const dnssec_binary_t *secret, uint8_t *mac, size_t *mac_len)
{
	dnssec_tsig_ctx_t *ctx = NULL;
	int ret = dnssec_tsig_new(&ctx, knot_tsig_rdata_alg(tsig), secret);
	if (ret != DNSSEC_EOK) {
		return KNOT_ERROR;
	}

	/* The message with its original ID. */
	uint8_t id[2];
	put16(id, knot_tsig_rdata_orig_id(tsig));
	dnssec_tsig_add(ctx, &(dnssec_binary_t){ .data = id, .size = 2 });
	dnssec_tsig_add(ctx, &(dnssec_binary_t){ .data = (uint8_t *)msg + 2, .size = len - 2 });

	/* TSIG variables: names in canonical (lowercase) form. */
	uint8_t name[KNOT_DNAME_MAXLEN];
	knot_dname_copy_lower(name, tsig->owner);
	dnssec_tsig_add(ctx, &(dnssec_binary_t){ .data = name, .size = knot_dname_size(name) });
	uint8_t cls_ttl[6] = { 0, KNOT_CLASS_ANY, 0, 0, 0, 0 };
	cls_ttl[2] = tsig->ttl >> 24;
	cls_ttl[3] = tsig->ttl >> 16;
	cls_ttl[4] = tsig->ttl >> 8;
	cls_ttl[5] = tsig->ttl;
	dnssec_tsig_add(ctx, &(dnssec_binary_t){ .data = cls_ttl, .size = 6 });
	knot_dname_copy_lower(name, knot_tsig_rdata_alg_name(tsig));
	dnssec_tsig_add(ctx, &(dnssec_binary_t){ .data = name, .size = knot_dname_size(name) });

	uint8_t vars[12];
	uint64_t time = knot_tsig_rdata_time_signed(tsig);
	put16(vars, time >> 32);
	put16(vars + 2, (time >> 16) & 0xffff);
	put16(vars + 4, time & 0xffff);
	put16(vars + 6, knot_tsig_rdata_fudge(tsig));
	put16(vars + 8, knot_tsig_rdata_error(tsig));
	put16(vars + 10, knot_tsig_rdata_other_data_length(tsig));
	dnssec_tsig_add(ctx, &(dnssec_binary_t){ .data = vars, .size = sizeof(vars) });
	dnssec_tsig_add(ctx, &(dnssec_binary_t){
		.data = (uint8_t *)knot_tsig_rdata_other_data(tsig),
		.size = knot_tsig_rdata_other_data_length(tsig) });

	*mac_len = dnssec_tsig_size(ctx);
	ret = dnssec_tsig_write(ctx, mac);
	dnssec_tsig_free(ctx);
	return ret == DNSSEC_EOK ? KNOT_EOK : KNOT_ERROR;
}

/* Append the RRs of `section` to `out`, without those `skip` matches. */
static int put_section(const knot_pkt_t *pkt, knot_section_t section,
                       bool (*skip)(const knot_rrset_t *), uint8_t *out,
                       size_t *pos, size_t max, uint16_t *count)
{
	const knot_pktsection_t *s = knot_pkt_section(pkt, section);
	*count = 0;
	for (uint16_t i = 0; i < s->count; i++) {
		const knot_rrset_t *rr = knot_pkt_rr(s, i);
		if (skip != NULL && skip(rr)) {
			continue;
		}
		/* Uncompressed: removing RRs would break compression pointers. */
		int ret = knot_rrset_to_wire(rr, out + *pos, max - *pos, NULL);
		if (ret < 0) {
			return ret;
		}
		*pos += ret;
		*count += 1;
	}
	return KNOT_EOK;
}

static bool skip_ignored(const knot_rrset_t *rr)
{
	return is_ignored(rr->owner);
}

static bool skip_tsig(const knot_rrset_t *rr)
{
	return rr->type == KNOT_RRTYPE_TSIG;
}

static knotd_state_t ignoreme_begin(knotd_state_t state, knot_pkt_t *pkt,
                                    knotd_qdata_t *qdata, knotd_mod_t *mod)
{
	(void)pkt;
	knot_pkt_t *query = qdata->query;
	if (qdata->type != KNOTD_QUERY_TYPE_UPDATE) {
		return state;
	}

	/* Anything to drop? */
	const knot_pktsection_t *updates = knot_pkt_section(query, KNOT_AUTHORITY);
	uint16_t dropped = 0;
	for (uint16_t i = 0; i < updates->count; i++) {
		dropped += is_ignored(knot_pkt_rr(updates, i)->owner);
	}
	if (dropped == 0) {
		return state;
	}

	/* The client's MAC must be valid, else knot shall reject the message. */
	const knot_rrset_t *tsig = query->tsig_rr;
	knotd_conf_t secret = { 0 };
	if (tsig != NULL) {
		uint8_t key[KNOT_DNAME_MAXLEN];
		knot_dname_copy_lower(key, tsig->owner);
		/* Section ids are matched by their raw (wire) form. */
		knotd_conf_t id = {
			.single.data = key, .single.data_len = knot_dname_size(key), .count = 1
		};
		secret = knotd_conf(mod, (const yp_name_t *)"\x03""key",
		                    (const yp_name_t *)"\x06""secret", &id);
		uint8_t mac[64];
		size_t mac_len = 0;
		if (secret.count == 0 ||
		    request_mac(tsig, query->wire, query->size,
		                &(dnssec_binary_t){ .data = (uint8_t *)secret.single.data,
		                                    .size = secret.single.data_len },
		                mac, &mac_len) != KNOT_EOK ||
		    mac_len != knot_tsig_rdata_mac_length(tsig) ||
		    memcmp(mac, knot_tsig_rdata_mac(tsig), mac_len) != 0) {
			knotd_conf_free(&secret);
			return state;
		}
	}

	/* Rewrite: header, question, prerequisites, kept updates, additional. */
	uint8_t out[KNOT_WIRE_MAX_PKTSIZE];
	size_t pos = KNOT_WIRE_HEADER_SIZE + knot_pkt_question_size(query);
	memcpy(out, query->wire, pos);
	uint16_t an, ns, ar;
	if (put_section(query, KNOT_ANSWER, NULL, out, &pos, sizeof(out), &an) != KNOT_EOK ||
	    put_section(query, KNOT_AUTHORITY, skip_ignored, out, &pos, sizeof(out), &ns) != KNOT_EOK ||
	    put_section(query, KNOT_ADDITIONAL, skip_tsig, out, &pos, sizeof(out), &ar) != KNOT_EOK ||
	    pos + query->tsig_wire.len > query->max_size) {
		knotd_mod_log(mod, LOG_WARNING, "failed to rewrite update");
		knotd_conf_free(&secret);
		return state;
	}
	put16(out + 6, an);
	put16(out + 8, ns);
	put16(out + 10, ar);

	if (tsig != NULL) {
		/* Raw TSIG with the client's MAC behind the new body. */
		memcpy(out + pos, query->tsig_wire.pos, query->tsig_wire.len);

		/* The parsed TSIG gets the MAC that matches the new body. */
		uint8_t mac[64];
		size_t mac_len = 0;
		int ret = request_mac(tsig, out, pos,
		                      &(dnssec_binary_t){ .data = (uint8_t *)secret.single.data,
		                                          .size = secret.single.data_len },
		                      mac, &mac_len);
		knotd_conf_free(&secret);
		if (ret != KNOT_EOK ||
		    knot_tsig_rdata_set_mac(query->tsig_rr, mac_len, mac) != KNOT_EOK) {
			knotd_mod_log(mod, LOG_WARNING, "failed to re-sign update");
			return state;
		}
	}

	memcpy(query->wire, out, pos + query->tsig_wire.len);
	query->size = pos;
	if (tsig != NULL) {
		query->tsig_wire.pos = query->wire + pos;
	}

	knotd_mod_log(mod, LOG_INFO, "ignored %u of %u updates", dropped, updates->count);
	return state;
}

static const yp_item_t ignoreme_conf[] = {
	{ NULL }
};

static int ignoreme_load(knotd_mod_t *mod)
{
	return knotd_mod_hook(mod, KNOTD_STAGE_BEGIN, ignoreme_begin);
}

KNOTD_MOD_API(ignoreme, KNOTD_MOD_FLAG_SCOPE_ANY | KNOTD_MOD_FLAG_OPT_CONF,
              ignoreme_load, NULL, ignoreme_conf, NULL);
