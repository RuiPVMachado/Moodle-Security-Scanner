#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Plugin/component inventory without fabricated CVE claims.

A plugin name alone is not a vulnerability, and a Moodle version is not the
plugin version.  This module only reports what it can prove:

* the component exists (its ``version.php`` is reachable), and
* whether that file exposes its PHP source/version to the web.

Plugin CVE claims require the plugin version and a plugin advisory database;
without both, the honest output is an inventory entry for manual review.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from modules.http import SecureSession, build_session

_COMPONENTS = (
    ("mod_forum", "mod/forum/version.php"),
    ("mod_book", "mod/book/version.php"),
    ("mod_data", "mod/data/version.php"),
    ("mod_quiz", "mod/quiz/version.php"),
    ("mod_scorm", "mod/scorm/version.php"),
    ("mod_wiki", "mod/wiki/version.php"),
    ("mod_workshop", "mod/workshop/version.php"),
    ("mod_choice", "mod/choice/version.php"),
    ("mod_feedback", "mod/feedback/version.php"),
    ("mod_lti", "mod/lti/version.php"),
    ("mod_assign", "mod/assign/version.php"),
    ("mod_lesson", "mod/lesson/version.php"),
    ("mod_glossary", "mod/glossary/version.php"),
    ("mod_h5pactivity", "mod/h5pactivity/version.php"),
    ("mod_attendance", "mod/attendance/version.php"),
    ("mod_customcert", "mod/customcert/version.php"),
    ("mod_certificate", "mod/certificate/version.php"),
    ("mod_questionnaire", "mod/questionnaire/version.php"),
    ("block_rss_client", "blocks/rss_client/version.php"),
    ("block_html", "blocks/html/version.php"),
    ("block_navigation", "blocks/navigation/version.php"),
    ("block_calendar_month", "blocks/calendar_month/version.php"),
    ("filter_multilang", "filter/multilang/version.php"),
    ("filter_mathjaxloader", "filter/mathjaxloader/version.php"),
    ("filter_tex", "filter/tex/version.php"),
    ("auth_oauth2", "auth/oauth2/version.php"),
    ("auth_ldap", "auth/ldap/version.php"),
    ("auth_shibboleth", "auth/shibboleth/version.php"),
    ("enrol_manual", "enrol/manual/version.php"),
    ("enrol_self", "enrol/self/version.php"),
    ("enrol_lti", "enrol/lti/version.php"),
    ("theme_boost", "theme/boost/version.php"),
    ("theme_classic", "theme/classic/version.php"),
    ("local_boost_union", "local/boost_union/version.php"),
    ("local_kopere", "local/kopere/version.php"),
    ("tool_mobile", "admin/tool/mobile/version.php"),
    ("tool_dataprivacy", "admin/tool/dataprivacy/version.php"),
    # Additional core and common third-party components. The per-run budget
    # (--max-tests) decides how many are probed.
    ("mod_page", "mod/page/version.php"),
    ("mod_resource", "mod/resource/version.php"),
    ("mod_url", "mod/url/version.php"),
    ("mod_folder", "mod/folder/version.php"),
    ("mod_label", "mod/label/version.php"),
    ("mod_chat", "mod/chat/version.php"),
    ("mod_survey", "mod/survey/version.php"),
    ("mod_imscp", "mod/imscp/version.php"),
    ("mod_choicegroup", "mod/choicegroup/version.php"),
    ("mod_hvp", "mod/hvp/version.php"),
    ("mod_bigbluebuttonbn", "mod/bigbluebuttonbn/version.php"),
    ("mod_subsection", "mod/subsection/version.php"),
    ("block_myoverview", "blocks/myoverview/version.php"),
    ("block_timeline", "blocks/timeline/version.php"),
    ("block_recent_activity", "blocks/recent_activity/version.php"),
    ("block_course_summary", "blocks/course_summary/version.php"),
    ("block_calendar_upcoming", "blocks/calendar_upcoming/version.php"),
    ("block_online_users", "blocks/online_users/version.php"),
    ("block_messages", "blocks/messages/version.php"),
    ("block_badges", "blocks/badges/version.php"),
    ("block_completionstatus", "blocks/completionstatus/version.php"),
    ("block_globalsearch", "blocks/globalsearch/version.php"),
    ("block_search_forums", "blocks/search_forums/version.php"),
    ("block_selfcompletion", "blocks/selfcompletion/version.php"),
    ("block_settings", "blocks/settings/version.php"),
    ("block_site_main_menu", "blocks/site_main_menu/version.php"),
    ("block_tags", "blocks/tags/version.php"),
    ("block_myprofile", "blocks/myprofile/version.php"),
    ("block_private_files", "blocks/private_files/version.php"),
    ("block_quiz_results", "blocks/quiz_results/version.php"),
    ("block_activity_modules", "blocks/activity_modules/version.php"),
    ("block_admin_bookmarks", "blocks/admin_bookmarks/version.php"),
    ("block_blog_menu", "blocks/blog_menu/version.php"),
    ("block_blog_recent", "blocks/blog_recent/version.php"),
    ("block_blog_tags", "blocks/blog_tags/version.php"),
    ("block_course_list", "blocks/course_list/version.php"),
    ("block_feedback", "blocks/feedback/version.php"),
    ("block_login", "blocks/login/version.php"),
    ("block_news_items", "blocks/news_items/version.php"),
    ("block_participants", "blocks/participants/version.php"),
    ("block_section_links", "blocks/section_links/version.php"),
    ("block_social_activities", "blocks/social_activities/version.php"),
    ("filter_activitynames", "filter/activitynames/version.php"),
    ("filter_algebra", "filter/algebra/version.php"),
    ("filter_censor", "filter/censor/version.php"),
    ("filter_emoji", "filter/emoji/version.php"),
    ("filter_displayh5p", "filter/displayh5p/version.php"),
    ("filter_emailprotect", "filter/emailprotect/version.php"),
    ("filter_glossary", "filter/glossary/version.php"),
    ("filter_mediaplugin", "filter/mediaplugin/version.php"),
    ("filter_tidy", "filter/tidy/version.php"),
    ("filter_urltolink", "filter/urltolink/version.php"),
    ("auth_cas", "auth/cas/version.php"),
    ("auth_db", "auth/db/version.php"),
    ("auth_email", "auth/email/version.php"),
    ("auth_fc", "auth/fc/version.php"),
    ("auth_imap", "auth/imap/version.php"),
    ("auth_manual", "auth/manual/version.php"),
    ("auth_mnet", "auth/mnet/version.php"),
    ("auth_none", "auth/none/version.php"),
    ("auth_radius", "auth/radius/version.php"),
    ("auth_webservice", "auth/webservice/version.php"),
    ("enrol_category", "enrol/category/version.php"),
    ("enrol_cohort", "enrol/cohort/version.php"),
    ("enrol_database", "enrol/database/version.php"),
    ("enrol_external", "enrol/external/version.php"),
    ("enrol_fee", "enrol/fee/version.php"),
    ("enrol_flatfile", "enrol/flatfile/version.php"),
    ("enrol_guest", "enrol/guest/version.php"),
    ("enrol_imsenterprise", "enrol/imsenterprise/version.php"),
    ("enrol_ldap", "enrol/ldap/version.php"),
    ("enrol_meta", "enrol/meta/version.php"),
    ("enrol_mnet", "enrol/mnet/version.php"),
    ("enrol_paypal", "enrol/paypal/version.php"),
    ("theme_fordson", "theme/fordson/version.php"),
    ("theme_remui", "theme/remui/version.php"),
    ("theme_adaptable", "theme/adaptable/version.php"),
    ("theme_moove", "theme/moove/version.php"),
    ("theme_efluid", "theme/efluid/version.php"),
    ("theme_snap", "theme/snap/version.php"),
    ("qtype_calculated", "question/type/calculated/version.php"),
    ("qtype_formulas", "question/type/formulas/version.php"),
    ("qtype_multichoice", "question/type/multichoice/version.php"),
    ("qtype_truefalse", "question/type/truefalse/version.php"),
    ("qtype_shortanswer", "question/type/shortanswer/version.php"),
    ("qtype_essay", "question/type/essay/version.php"),
    ("qtype_match", "question/type/match/version.php"),
    ("qtype_numerical", "question/type/numerical/version.php"),
    ("qtype_ddwtos", "question/type/ddwtos/version.php"),
    ("qtype_ddimageortext", "question/type/ddimageortext/version.php"),
    ("qtype_gapselect", "question/type/gapselect/version.php"),
    ("availability_completion", "availability/condition/completion/version.php"),
    ("availability_date", "availability/condition/date/version.php"),
    ("availability_grade", "availability/condition/grade/version.php"),
    ("availability_group", "availability/condition/group/version.php"),
    ("availability_grouping", "availability/condition/grouping/version.php"),
    ("availability_profile", "availability/condition/profile/version.php"),
    ("contenttype_h5p", "contentbank/contenttype/h5p/version.php"),
    ("dataformat_csv", "dataformat/csv/version.php"),
    ("dataformat_excel", "dataformat/excel/version.php"),
    ("dataformat_json", "dataformat/json/version.php"),
    ("dataformat_ods", "dataformat/ods/version.php"),
    ("dataformat_pdf", "dataformat/pdf/version.php"),
    ("mlbackend_php", "mlbackend/php/version.php"),
    ("payment_paypal", "payment/gateway/paypal/version.php"),
    ("payment_stripe", "payment/gateway/stripe/version.php"),
)

_VERSION_KEYS = ("version", "release", "requires", "component", "maturity")


class MoodlePluginTester:
    def __init__(
        self,
        target_url: str,
        logger: Optional[logging.Logger] = None,
        timeout: int = 30,
        proxy: Optional[str] = None,
        cookies: Optional[Dict[str, str]] = None,
        delay: float = 0,
        user_agent: Optional[str] = None,
        verify_ssl: bool = True,
        session: Optional[SecureSession] = None,
        deep: bool = False,
        max_tests: int = 50,
        **_: Any,
    ) -> None:
        self.target_url = target_url.rstrip("/") + "/"
        self.timeout = timeout
        self.deep = deep
        self.max_tests = max(1, max_tests)
        self.version_info: Dict[str, Any] = {}
        self.logger = logger or logging.getLogger("MoodlePluginTester")
        self.session = session or build_session(
            verify_ssl=verify_ssl,
            timeout=timeout,
            user_agent=user_agent,
            proxy=proxy,
            cookies=cookies,
        )

    def set_version_info(self, version_info: Dict[str, Any]) -> None:
        self.version_info = version_info or {}

    def run_tests(self) -> Dict[str, List[Dict[str, Any]]]:
        results: Dict[str, List[Dict[str, Any]]] = {"vulnerabilities": [], "info": []}
        detected: List[str] = []

        for component, path in _COMPONENTS[: self.max_tests]:
            url = self.target_url + path
            try:
                response = self.session.get(url, timeout=self.timeout, allow_redirects=False)
            except Exception:
                continue
            if response.status_code != 200:
                continue

            detected.append(component)
            body = response.text or ""
            source = self._extract_php_source(body)
            if source:
                results["vulnerabilities"].append(
                    {
                        "title": f"Source de version.php exposto: {component}",
                        "description": (
                            "O ficheiro version.php do componente é servido como texto, "
                            "revelando a versão e caminhos internos. Isto facilita a "
                            "correspondência com advisories específicos do plugin."
                        ),
                        "severity": "Low",
                        "confidence": "high",
                        "evidence": source[:800],
                        "url": url,
                        "remediation": (
                            "Garantir que o PHP é executado e que ficheiros .php não são "
                            "servidos como texto; bloquear acesso direto a version.php."
                        ),
                        "cwe": "CWE-538",
                        "verified": True,
                        "source": "plugin",
                        "evidence_type": "passive",
                    }
                )

        if detected:
            results["info"].append(
                {
                    "title": "Componentes Moodle detetados",
                    "description": (
                        f"{len(detected)} componentes encontrados: "
                        + ", ".join(detected[:30])
                        + ". Inventário apenas; não implica vulnerabilidade."
                    ),
                    "severity": "Info",
                    "verified": True,
                    "source": "plugin",
                    "evidence_type": "info",
                }
            )
        else:
            results["info"].append(
                {
                    "title": "Inventário de plugins limitado",
                    "description": (
                        "Não foi possível confirmar componentes por version.php. "
                        "O servidor pode bloquear estes caminhos ou o alvo não é Moodle."
                    ),
                    "severity": "Info",
                    "verified": True,
                    "source": "plugin",
                    "evidence_type": "info",
                }
            )
        return results

    @staticmethod
    def _extract_php_source(body: str) -> Optional[str]:
        if "<?php" not in body or "$plugin->" not in body:
            return None
        lines = [line.strip() for line in body.splitlines() if line.strip()]
        relevant = [
            line
            for line in lines
            if "<?php" in line or any(key in line for key in _VERSION_KEYS)
        ]
        return "\n".join(relevant[:20]) if relevant else body[:800]
