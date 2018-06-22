<?php
/**
 * @wordpress-plugin
 * Plugin Name:       Wisc Content Auth LTI
 * Description:       LTI Integration for Pressbooks and Grassblade at UW-Madison. Based on the Candela LTI integration from Lumen Learning, but looks for a specified custom LTI parameter to use for the WordPress login id (instead of using the generated LTI user id)
 * Version:           0.2.7
 * Author:            UW-Madison Learning Solutions
 * Author URI:
 * Text Domain:       lti
 * License:           MIT
 * Network: True
 * GitHub Plugin URI:
 */

//namespace WiscLTI;

use \WiscLTI\OAuth\OAuthSignatureMethod_HMAC_SHA1;
use \WiscLTI\OAuth\OAuthConsumer;
use \WiscLTI\OAuth\OAuthRequest;
use \WiscLTI\Util\Net;


// If file is called directly, abort.
if ( ! defined( 'ABSPATH' ) ) exit;

// Do our necessary plugin setup and add_action routines.
WISCPB_LTI::init();

class WISCPB_LTI {

  const DEBUG_LOG = TRUE;

  /**
   * Takes care of registering our hooks and setting constants.
   */
  public static function init() {
    if (isset($_GET['content_only'])) {
      add_action( 'init', array( __CLASS__, 'init_no_navigation' ) );
    }

    // Table name is always root (site)
    define('WISCPB_LTI_TABLE', 'wp_wiscpblti');
    define('WISCPB_LTI_DB_VERSION', '1.2');
    define('WISCPB_LTI_CAP_LINK_LTI', 'wiscpb link lti launch');
    define('WISCPB_LTI_USERMETA_LASTLINK', 'wiscpblti_lastkey');
    define('WISCPB_LTI_USERMETA_ENROLLMENT', 'wiscpblti_enrollment_record');
    define('WISCPB_LTI_PASSWORD_LENGTH', 32);

    //E. Scull: Add new constants ======================================
    define('WISC_LTI_LOGIN_ID_POST_PARAM', 'custom_canvas_user_login_id');
    define('WISC_LTI_LOGIN_EMAIL_POST_PARAM', 'lis_person_contact_email_primary');
    define('WISC_DEFAULT_EMAIL_DOMAIN', 'wisc.edu');
    define('WISC_OUTCOMES_TABLE', 'wp_wiscltioutcomes');
    // =================================================================

    register_activation_hook( __FILE__, array( __CLASS__, 'activate' ) );
    register_uninstall_hook(__FILE__, array( __CLASS__, 'deactivate') );

    add_action( 'init', array( __CLASS__, 'update_db' ) );
    add_action( 'init', array( __CLASS__, 'add_rewrite_rule' ) );
    add_action( 'init', array( __CLASS__, 'setup_capabilities' ) );
    add_action( 'query_vars', array( __CLASS__, 'query_vars' ) );
    add_action( 'parse_request', array( __CLASS__, 'parse_request' ) );
    add_action('add_meta_boxes', array(__CLASS__,'addLTILink'));

      add_action('admin_menu', array(__CLASS__, 'setup_lti_admin_menus'));



      // Respond to LTI launches
    add_action( 'lti_setup', array( __CLASS__, 'lti_setup' ) );
    add_action( 'lti_launch', array( __CLASS__, 'lti_launch') );

    add_action('lti_outcome', array(__CLASS__, 'sendGrade'), 10, 4);

//    add_action('admin_menu', array( __CLASS__, 'admin_menu'));

    add_action('post_submitbox_misc_actions', array(__CLASS__, 'createPostRestrictField'));
    add_action('save_post', array(__CLASS__, 'savePostRestrictField'));
    add_action('wp', array(__CLASS__, 'restrict_access'));

    define('WISCPB_LTI_TEACHERS_ONLY', 'wiscpb_lti_teachers_only');
    add_option( WISCPB_LTI_TEACHERS_ONLY, false );
	}

  function setup_lti_admin_menus() {
        add_options_page('LTI Restrictions', 'LTI Restriction Settings', 'manage_options',
            'lti_settings', array(__CLASS__,'lti_settings'));
  }

  function lti_settings() {
        if (!current_user_can('manage_options')) {
            wp_die('You do not have sufficient permissions to access this page.');
        }

        echo "<h1>LTI Restriction Settings</h1>";

        if (isset($_POST['submit']) && $_SERVER["REQUEST_METHOD"] == "POST") {
            if(!empty($_POST['restrict-lti'])) {
                $restrict_lti = esc_attr($_POST['restrict-lti']);
                update_option("restrict-lti", $restrict_lti);
            } else {
                update_option("restrict-lti", "0");
            }

            echo "<div><h2 class='creport-info-message'>Settings saved</h2></div>";
        }

        $restrict_lti = get_option('restrict-lti');


        ?>

        <form method="POST" action="">
            <p style="width:200px;"><?php _e("Restrict page views to only LTI launches", 'lti_settings'); ?>
                <input type="checkbox" id="restrict-lti" name="restrict-lti" value="1"<?php checked( '1' , $restrict_lti) ?>"/>
            </p>
            <br /><br />
            <input name="submit" type="submit" id="submit" value="Save" class="button-primary" />
        </form>

        <?php

    }

  public static function init_no_navigation() {
    wp_enqueue_style('wisc-lti-nav', plugins_url('no-navigation.css', __FILE__));
  }

  public static function addLTILink($post){
        add_meta_box( 'lti_meta_box', __( 'LTI Information', 'lti_meta' ), array(__CLASS__, 'build_lti_link'), 'post', 'normal', 'low');
        add_meta_box( 'lti_meta_box', __( 'LTI Information', 'lti_meta' ), array(__CLASS__, 'build_lti_link'), 'page', 'normal', 'low');


    }

  public static function build_lti_link(){
        global $wpdb;
        $current_blog = get_current_blog_id();

        switch_to_blog(1);
        $table_name = $wpdb->base_prefix . "postmeta";
        $sql = "SELECT * FROM ". $table_name ." WHERE meta_key = '_lti_consumer_key'";
        $consumer_key = $wpdb->get_row($sql);

        $sql = "SELECT * FROM ".$table_name." WHERE meta_key = '_lti_consumer_secret'";
        $consumer_secret = $wpdb->get_row($sql);

        switch_to_blog($current_blog);
        $post_id = get_the_ID();
        $link = get_home_url(1) .'/api/lti/'.$current_blog.'?page_id='.$post_id;

//	    echo $consumer_key;
        echo '<div>
                LTI Link: <strong>'.$link.'</strong></br>
                Consumer Key: <strong>'. $consumer_key->meta_value . '</strong></br>
                Consumer Secret: <strong>' . $consumer_secret->meta_value. '</strong>
            </div>';
    }

  /**
   * Ensure all dependencies are set and available.
   */
  public static function activate() {
    // Require lti plugin
    if ( ! is_plugin_active( 'lti/lti.php' ) and current_user_can( 'activate_plugins' ) and !is_multisite()) {
      wp_die('This plugin requires a multisite instance and the LTI plugin to be installed and active. <br /><a href="' . admin_url( 'plugins.php' ) . '">&laquo; Return to Plugins</a>');' )';
    }

    WISCPB_LTI::create_db_table();
  }

  /**
   * Do any necessary cleanup.
   */
  public static function deactivate() {
    WISCPB_LTI::remove_db_table();
  }

  public static function createPostRestrictField(){
      $post_id = get_the_ID();

      if (!(get_post_type($post_id) == 'post' || get_post_type($post_id) == 'page' ||
          get_post_type($post_id) == 'chapter')) {
          return;
      }

      $value = get_post_meta($post_id, 'post_restrict_lti', true);
      wp_nonce_field('restrict_nonce'.$post_id, 'restrict_nonce');

      $buttonText = 'Restrict content to LTI Launches';

      $restrict_lti = get_option('restrict-lti');
      if ($restrict_lti == 1){
          $buttonText = 'Restricted at the site level';
          $value = true;
      }

      ?>
      <div class="misc-pub-section misc-pub-section-first">
          <label><input type="checkbox" value="1" <?php checked($value, true, true); disabled($restrict_lti == 1, true, true); ?> name="post_restrict_lti" /><?php _e($buttonText); ?></label>
      </div>
      <?php
  }

  public static function savePostRestrictField($post_id){
      if (defined('DOING_AUTOSAVE') && DOING_AUTOSAVE) {
          return;
      }

      if (
          !isset($_POST['restrict_nonce']) ||
          !wp_verify_nonce($_POST['restrict_nonce'], 'restrict_nonce'.$post_id)
      ) {
          return;
      }

      if (!current_user_can('edit_post', $post_id)) {
          return;
      }

      $restrict_lti = get_option('restrict-lti');
      if ($restrict_lti == 1){
          return;
      }

      if (isset($_POST['post_restrict_lti'])) {
          update_post_meta($post_id, 'post_restrict_lti', $_POST['post_restrict_lti']);
      } else {
          delete_post_meta($post_id, 'post_restrict_lti');
      }
  }

  public static function restrict_access(){

      $post_id = get_the_ID();
      $value = get_post_meta($post_id, 'post_restrict_lti', true);

      $restrict_lti = get_option('restrict-lti');
      $should_restrict = $value || $restrict_lti == 1;

      if (current_user_can('edit_posts') || isset($_REQUEST['lti_context_id']) || !$should_restrict){
          return;
      } else {
          // Not through LTI or an editing user, redirect to 403
          global $wp_query;
          $wp_query->set_403();
          status_header( 403 );
          get_template_part( 403 ); exit();
      }

  }

  /**
   * Responder for action lti_launch.
   */
  public static function lti_launch() {
    global $wp;
      $current_user = wp_get_current_user();

      WISCPB_LTI::save_outcome_info($_POST['lis_outcome_service_url'],
          $wp->query_vars['page_id'],
          $current_user->ID, $wp->query_vars['blog'], $_POST["lis_result_sourcedid"]);
//      WISCPB_LTI::sendGrade(.5, $current_user->ID, $wp->query_vars['page_id'], $wp->query_vars['blog']);
    // allows deep links with an LTI launch urls like:
    // <wiscpb>/api/lti/BLOGID?page_title=page_name
    // <wiscpb>/api/lti/BLOGID?page_title=section_name%2Fpage_name
    if ( ! empty($wp->query_vars['page_title'] ) ) {
      switch_to_blog((int)$wp->query_vars['blog']);
      $page = $wp->query_vars['page_title'];
      if ( $page[0] ==  '/' ){
        $slash = '';
      } else {
        $slash = '/';
      }

      // todo make all the hide_* parameters copy over?
      // If it's a deep LTI link default to showing content_only
      wp_redirect( get_bloginfo('wpurl') . $slash . $page . "?content_only" );
      exit;
    }

    // allows deep links with an LTI launch urls like:
    // <wiscpb>/api/lti/BLOGID?page_id=10
    if ( ! empty($wp->query_vars['page_id'] ) && is_numeric($wp->query_vars['page_id']) ) {
      switch_to_blog((int)$wp->query_vars['blog']);
      $url = get_bloginfo('wpurl') . "?p=" . $wp->query_vars['page_id'] . "&content_only&lti_context_id=" . $wp->query_vars['context_id'];
      if (! empty($wp->query_vars['ext_post_message_navigation'] )){
        $url = $url . "&lti_nav";
      }
      wp_redirect( $url );
      exit;
    }

    // allows deep links with an LTI custom parameter like:
    // custom_page_id=10
    if ( ! empty($wp->query_vars['custom_page_id'] ) && is_numeric($wp->query_vars['custom_page_id']) ) {
      switch_to_blog((int)$wp->query_vars['blog']);
      wp_redirect( get_bloginfo('wpurl') . "?p=" . $wp->query_vars['custom_page_id'] . "&content_only&lti_context_id=" . $wp->query_vars['context_id'] );
      exit;
    }

    if ( ! empty($wp->query_vars['resource_link_id'] ) ) {
      $map = WISCPB_LTI::get_lti_map($wp->query_vars['resource_link_id']);
      if ( ! empty( $map->target_action ) ) {
        wp_redirect( $map->target_action );
        exit;
      }
    }
    // Currently just redirect to the blog/site homepage.
    if ( ! ( empty( $wp->query_vars['blog'] ) ) ){
      switch_to_blog((int)$wp->query_vars['blog']);
      wp_redirect( get_bloginfo('wpurl') . '/?content_only' );
      exit;
    }

    // redirect to primary site
    wp_redirect( get_site_url( 1 ) );
    exit;
  }

  /**
   * Do any setup necessary to manage LTI launches.
   */
  public static function lti_setup() {
    // Manage authentication and account creation.
    WISCPB_LTI::lti_accounts();

    // If this is a valid user store the resource_link_id so we have it later.
    if ( WISCPB_LTI::user_can_map_lti_links() ) {
      $current_user = wp_get_current_user();
      update_user_meta( $current_user->ID, WISCPB_LTI_USERMETA_LASTLINK, $_POST['resource_link_id'] );
    }
  }

  /**
   * Take care of authenticating the incoming user and creating an account if required.
   */
  public static function lti_accounts() {
      global $wp;

    // Used to track if we call wp_logout() since is_user_logged_in() will still
    // report true after our call to that.
    // @see http://wordpress.stackexchange.com/questions/13087/wp-logout-not-logging-me-out
    $logged_out = FALSE;

    // if we do not have an external user_id skip account stuff.
    if ( empty($_POST[WISC_LTI_LOGIN_ID_POST_PARAM]) ) {
      return;
    }

    // We also require that this external id be an email address so that it can be used to create/identify a user.
    if ( ! is_email( $_POST[WISC_LTI_LOGIN_ID_POST_PARAM] ) ) {
      wp_die( 'Canvas ID provided to LTI tool ("' . $_POST[WISC_LTI_LOGIN_ID_POST_PARAM] . '") is not a valid email address.' );
    }

    // Find user account (if any) with matching ID
    //E. Scull: Use login (username) instead of external id
    //$user = WISCPB_LTI::find_user_by_external_id( $_POST['user_id'] );
    $user = WISCPB_LTI::find_user_by_login( $_POST[WISC_LTI_LOGIN_ID_POST_PARAM] );

    //E. Scull: Moved here, was below the following is_user_logged_in() if block
    if ( empty($user) ) {
      // Create a user account if we do not have a matching account
      $user = WISCPB_LTI::create_user_account( $_POST[WISC_LTI_LOGIN_ID_POST_PARAM], $_POST[WISC_LTI_LOGIN_EMAIL_POST_PARAM] );
    }

    //E. Scull - update user if any role. TODO: Go ahead and add first/last name when creating user. Why is this a separate function? Why only teachers?
    //WISCPB_LTI::update_user_if_teacher( $user );
    WISCPB_LTI::update_user( $user );



    if ( is_user_logged_in() ) {
      //E. Scull: If the logged in user's login name doesn't match what's passed from LTI, log them out.
      $current_user = wp_get_current_user();
      if($current_user->ID !== $user->ID) {
        wp_logout();
        $logged_out = TRUE;
      }
      else {
        $user = $current_user;
      }
    }



    // If the user is not currently logged in... authenticate as the matched account.
    if ( ! is_user_logged_in() || $logged_out ) {
      WISCPB_LTI::login_user_no_password( $user->ID );
    }

    // Associate the user with this blog as a subscriber if not already associated.
    $blog = (int)$wp->query_vars['blog'];
    if ( ! empty( $blog ) && ! is_user_member_of_blog( $user->ID, $blog ) ) {
      if( WISCPB_LTI::is_lti_user_allowed_to_subscribe($blog)){
        add_user_to_blog( $blog, $user->ID, 'subscriber');
        WISCPB_LTI::record_new_register($user, $blog);
      }
    }
  }

  /**
   * Checks if the settings of the book allow this user to subscribe
   * That means that either all LTI users are, or only teachers/admins
   *
   * If the blog's WISCPB_LTI_TEACHERS_ONLY option is 1 then only teachers
   * are allowed
   *
   * @param $blog
   */
  public static function is_lti_user_allowed_to_subscribe($blog){
    $role = WISCPB_LTI::highest_lti_context_role();
    if( $role == 'admin' || $role == 'teacher' ) {
      return true;
    } else {
      // Switch to the target blog to get the correct option value
      $curr = get_current_blog_id();
      switch_to_blog($blog);
      $teacher_only = get_option(WISCPB_LTI_TEACHERS_ONLY);
      switch_to_blog($curr);

      return $teacher_only != 1;
    }
  }

  /**
   * Create a user account corresponding to the current incoming LTI request.
   *
   * @param string $username
   *   The username of the new account to create. If this username already exists
   *   we return the corresponding user account.
   *
   * @todo consider using 'lis_person_contact_email_primary' if passed as email.
   * @return the newly created user account.
   */
  public static function create_user_account( $username, $email ) {
    $existing_user = get_user_by('login', $username);

    if ( ! empty($existing_user) ) {
      return $existing_user;
    }
    else {
        $password = wp_generate_password( WISCPB_LTI_PASSWORD_LENGTH, true);

      //E. Scull: TODO, add user's name and other details here too.
      $user_id = wp_create_user( $username, $password, $username );
      if ( is_wp_error( $user_id ) ) {
        wp_die( 'Failed to create new Pressbooks user with a username and email of "' . $username . '".  Does an account already exist for that email address?' );
      }
      
      $user = new WP_User( $user_id );
      $user->set_role( 'subscriber' );
//        echo $username.'<br>';
//        echo $email.'<br>';
//        echo $password.'<br>';
//        echo $user_id->get_error_message().'<br>';
//        die();
      return $user;
    }
  }

  public static function record_new_register($user, $blog){
    //E. Scull: Comment out role-related filtering; we want names and default email for everyone (including students)

    $roles = '';
    if (isset($_POST['ext_roles'])) {
      // Canvas' more correct roles values are here
      $roles = $_POST['ext_roles'];
    } else if (isset($_POST['roles'])) {
      $roles = $_POST['roles'];
    }

    $data = array(
        "lti_user_id"=>$_POST[WISC_LTI_LOGIN_ID_POST_PARAM],
        "lti_context_id"=>$_POST['context_id'],
        "lti_context_name"=>$_POST['context_title'],
        "lti_school_id"=>$_POST['tool_consumer_instance_guid'],
        "lti_school_name"=>$_POST['tool_consumer_instance_name'],
        "lti_role"=>$roles,
        "timestamp"=>time(),
    );

    //$role = WISCPB_LTI::highest_lti_context_role();

    //if ( $role == 'admin' || $role == 'teacher' ) {
      if ( !empty( $_POST['lis_person_name_given'] ) ) {
        $data['lti_first_name'] = $_POST['lis_person_name_given'];
      }
      if ( !empty( $_POST['lis_person_name_family'] ) ) {
        $data['lti_last_name'] = $_POST['lis_person_name_family'];
      }
      if ( !empty( $_POST['lis_person_contact_email_primary'] ) ) {
        $data['lti_email'] = $_POST['lis_person_contact_email_primary'];
      }
    //}

    $curr = get_current_blog_id();
    switch_to_blog($blog);
    update_user_option( $user->ID, WISCPB_LTI_USERMETA_ENROLLMENT, $data );
    switch_to_blog($curr);
  }

  // Should use email from LTI instead?
  public static function default_lti_email( $username ) {
    return $username . '@' . WISC_DEFAULT_EMAIL_DOMAIN;
  }

  /**
   * Update user's first/last names
   * If their name wasn't sent, set their name as their role
   *
   * @param $user
   *
   */
  public static function update_user( $user ) {
    $userdata = ['ID' => $user->ID];
    if( !empty($_POST['lis_person_name_family']) || !empty($_POST['lis_person_name_given']) ){
      $userdata['last_name'] = $_POST['lis_person_name_family'];
      $userdata['first_name'] = $_POST['lis_person_name_given'];
    }

    if( !empty($userdata['last_name']) || !empty($userdata['first_name']) ) {
      wp_update_user($userdata);
    }
  }

  /**
   * Parses the LTI roles into an array
   *
   * @return array
   */
  public static function get_current_launch_roles(){
    $roles = [];
    if( isset($_POST['ext_roles']) ) {
      // Canvas' more correct roles values are here
      $roles = $_POST['ext_roles'];
    } elseif (isset($_POST['roles'])){
      $roles = $_POST['roles'];
    } else {
      return $roles;
    }

    $roles = explode(",", $roles);
    return array_filter(array_map('trim', $roles));
  }

  /**
   * Returns the user's highest role, which in this context is defined by this order:
   *
   * Admin
   * Teacher
   * Designer
   * TA
   * Student
   * Other
   *
   * @return string admin|teacher|designer|ta|learner|other
   */
  public static function highest_lti_context_role(){
    $roles = WISCPB_LTI::get_current_launch_roles();
    if (in_array('urn:lti:instrole:ims/lis/Administrator', $roles) || in_array('Administrator', $roles)):
      return "admin";
    elseif (in_array('urn:lti:role:ims/lis/Instructor', $roles) || in_array('Instructor', $roles)):
      return "teacher";
    elseif (in_array('urn:lti:role:ims/lis/ContentDeveloper', $roles) || in_array('ContentDeveloper', $roles)):
      return "designer";
    elseif (in_array('urn:lti:role:ims/lis/TeachingAssistant', $roles) || in_array('TeachingAssistant', $roles)):
      return "ta";
    elseif (in_array('urn:lti:role:ims/lis/Learner', $roles) || in_array('Learner', $roles)):
      return "learner";
    else:
      return "other";
    endif;
  }

  //E. Scull - Add function to find user by login name (username) instead of external_id meta field
  public static function find_user_by_login( $login ) {
    switch_to_blog(1);
    $user = get_user_by( 'login', $login );
    if ( empty ( $user ) ) {
      $user = get_user_by( 'email', $login );
    }
    restore_current_blog();

    return $user;
  }

  /**
   * login the current user (if not logged in) as the user matching $user_id
   *
   * @see http://wordpress.stackexchange.com/questions/53503/can-i-programmatically-login-a-user-without-a-password
   */
  public static function login_user_no_password( $user_id ) {
    //E. Scull: Finding that user is still considered logged in even after wp_logout() is run above.
    //Remove is_user_logged_in() check to force user switch if this function is run.
    //if ( ! is_user_logged_in() ) {
      wp_clear_auth_cookie();
      wp_set_current_user( $user_id );
      wp_set_auth_cookie( $user_id );
    //}
  }

  /**
   * Add our LTI api endpoint vars so that wordpress "understands" them.
   */
  public static function query_vars( $query_vars ) {
    $query_vars[] = '__wiscpblti';
    $query_vars[] = 'resource_link_id';
    $query_vars[] = 'target_action';
    $query_vars[] = 'page_title';
    $query_vars[] = 'page_id';
    $query_vars[] = 'action';
    $query_vars[] = 'ID';
    $query_vars[] = 'context_id';
    $query_vars[] = 'wiscpb-lti-nonce';
    $query_vars[] = 'custom_page_id';
    $query_vars[] = 'ext_post_message_navigation';

    return $query_vars;
  }

  /**
   * Update the database
   */
  public static function update_db() {
    switch_to_blog(1);
    $version = get_option( 'wiscpb_lti_db_version', '');
    restore_current_blog();

    if (empty($version) || $version == '1.0') {
      $meta_type = 'user';
      $user_id = 0; // ignored since delete all = TRUE
      $meta_key = 'wiscpblti_lti_info';
      $meta_value = ''; // ignored
      $delete_all = TRUE;
      delete_metadata( $meta_type, $user_id, $meta_key, $meta_value, $delete_all );

      switch_to_blog(1);
      update_option( 'wiscpb_lti_db_version', WISCPB_LTI_DB_VERSION );
      restore_current_blog();
    }
    if ( $version == '1.1' ) {
      // This also updates the table.
      WISCPB_LTI::create_db_table();
    }
  }

  /**
   * Add our LTI resource_link_id mapping api endpoint
   */
  public static function add_rewrite_rule() {
    add_rewrite_rule( '^api/wiscpblti?(.*)', 'index.php?__wiscpblti=1&$matches[1]', 'top');
  }

  /**
   * Setup our new capabilities.
   */
  public static function setup_capabilities() {
    global $wp_roles;

    $wp_roles->add_cap('administrator', WISCPB_LTI_CAP_LINK_LTI);
    $wp_roles->add_cap('editor', WISCPB_LTI_CAP_LINK_LTI);
  }

  /**
   * Implementation of action 'parse_request'.
   *
   * @see http://codex.wordpress.org/Plugin_API/Action_Reference/parse_request
   */
  public static function parse_request() {
    global $wp, $wpdb;

    if ( WISCPB_LTI::user_can_map_lti_links() && isset( $wp->query_vars['__wiscpblti'] ) && !empty($wp->query_vars['__wiscpblti'] ) ) {
      // Process adding link associations
      if ( wp_verify_nonce($wp->query_vars['wiscpb-lti-nonce'], 'mapping-lti-link') &&
           ! empty( $wp->query_vars['resource_link_id']) &&
           ! empty( $wp->query_vars['target_action'] ) ) {
        // Update db record everything is valid
        $map = WISCPB_LTI::get_lti_map($wp->query_vars['resource_link_id'] );

        $current_user = wp_get_current_user();
        $values = array(
          'resource_link_id' => $wp->query_vars['resource_link_id'],
          'target_action' => $wp->query_vars['target_action'],
          'user_id' => $current_user->ID,
          'blog_id' => $wp->query_vars['blog'],
        );
        $value_format = array(
          '%s',
          '%s',
          '%d',
          '%d',
        );

        if ( ! empty( $map->target_action ) ) {
          // update the existing map.
          $where = array( 'resource_link_id' => $wp->query_vars['resource_link_id'] );
          $where_format = array( '%s' );
          $result = $wpdb->update(WISCPB_LTI_TABLE, $values, $where, $value_format, $where_format );
        }
        else {
          // map was empty... insert the new map.
          $result = $wpdb->insert(WISCPB_LTI_TABLE, $values, $value_format );
        }

        if ( $result === FALSE ) {
          // die with error error
          wp_die('Failed to map resource_link_id(' . $wp->query_vars['resource_link_id'] . ') to url(' . $wp->query_vars['target_action']) . ')';
        }
      }

      // Process action items.
      if ( wp_verify_nonce($wp->query_vars['wiscpb-lti-nonce'], 'unmapping-lti-link') && ! empty( $wp->query_vars['action'] ) ) {
        switch ( $wp->query_vars['action'] ) {
          case 'delete':
            if ( !empty($wp->query_vars['ID'] && is_numeric($wp->query_vars['ID']))) {
              $wpdb->delete( WISCPB_LTI_TABLE, array( 'ID' => $wp->query_vars['ID'] ) );
            }
            break;
        }
      }

      // If we have a target_action, redirect to it, otherwise redirect back to home.
      if ( ! empty( $wp->query_vars['target_action'] ) ) {
        wp_redirect( $wp->query_vars['target_action'] );
      }
      else if ( ! empty($_SERVER['HTTP_REFERER'] ) ) {
        wp_redirect( $_SERVER['HTTP_REFERER'] );
      }
      else {
        wp_redirect( home_url() );
      }
      exit();
    }

  }

  /**
   * Given a resource_link_id return the mapping row for that resource_link_id.
   *
   * @param string resource_link_id
   *   The resource_link_id to get the row for. If empty the last LTI launch link
   *   for the user if user is logged in will be used.
   *
   * @return object
   *  Either the matching row or an object with just the resource_link_id set.
   */
  public static function get_lti_map( $resource_link_id = '' ) {
    global $wpdb;

    if ( empty( $resource_link_id ) && is_user_logged_in() ) {
      $current_user = wp_get_current_user();
      // Make sure query is ran against primary site since usermeta was set via
      // lti_setup action.
      switch_to_blog(1);
      $resource_link_id = get_user_meta( $current_user->ID, WISCPB_LTI_USERMETA_LASTLINK, TRUE );
      restore_current_blog();
    }

    $table_name = WISCPB_LTI_TABLE;
    $sql = $wpdb->prepare("SELECT * FROM $table_name WHERE resource_link_id  = %s", $resource_link_id);

    $map = $wpdb->get_row( $sql );

    if ( empty( $map ) ) {
      $map = new stdClass;
      $map->resource_link_id = $resource_link_id;
    }

    return $map;

  }

  public static function get_maps_by_target_action( $target_action = '' ) {
    global $wpdb;

    if ( empty( $target_action ) && is_single() ) {
      $target_action = get_permalink();
    }

    $table_name = WISCPB_LTI_TABLE;
    $sql = $wpdb->prepare("SELECT * FROM $table_name WHERE target_action = %s", $target_action);
    return $wpdb->get_results($sql);
  }

  /**
   * If we have an authenticated user and unmapped LTI launch add a link to
   * associate current page with the LTI launch.
   */
  public static function content_map_lti_launch( $content ) {
    if ( is_single()
        && WISCPB_LTI::user_can_map_lti_links()
        && empty($wp->query_vars['page_title'])
        && ! isset($_GET['content_only']) ) {

      $map = WISCPB_LTI::get_lti_map();
      $target_action = get_permalink();
      $resource_link_id = '';
      $links = array();

      if ( empty( $map ) || ( empty( $map->target_action ) && ! empty( $map->resource_link_id ) ) ) {
        $resource_link_id = $map->resource_link_id;
        // Map is either not set at all or needs to be set, inject content to do so.
        $text = __('Add LTI link');
        $hover = __('resource_link_id(##RES##)');
        $url = get_site_url(1) . '/api/wiscpblti';
        $url = wp_nonce_url($url, 'mapping-lti-link', 'wiscpb-lti-nonce');
        $url .= '&resource_link_id=' . urlencode($map->resource_link_id) . '&target_action=' . urlencode( $target_action ) . '&blog=' . get_current_blog_id();
        $links['add'] = '<div class="lti addmap"><a class="btn blue" href="' . $url . '" title="' . esc_attr( str_replace('##RES##', $map->resource_link_id, $hover) ) . '">' . $text . '</a></div>';
      }

      $maps = WISCPB_LTI::get_maps_by_target_action();
      if ( ! empty( $maps ) ) {
        $base_url = get_site_url(1) . '/api/wiscpblti';
        $base_url = wp_nonce_url($base_url, 'unmapping-lti-link', 'wiscpb-lti-nonce');
        $text = __('Remove LTI link');
        $hover = __('resource_link_id(##RES##)');
        foreach ( $maps as $map ) {
          if ($map->resource_link_id == $resource_link_id ) {
            // don't include add and delete link
            unset($links['add']);
          }
          $url = $base_url . '&action=delete&ID=' . $map->ID . '&blog=' . get_current_blog_id();
          $links[] = '<a class="btn red" href="' . $url . '"title="' . esc_attr( str_replace('##RES##', $map->resource_link_id, $hover) ) . '">' . $text . '</a>';
        }
      }

      if ( ! empty( $links ) ) {
        $content .= '<div class="lti-mapping"><ul class="lti-mapping"><li>' . implode('</li><li>', $links) . '</li></ul></div>';
      }
    }
    return $content;
  }

  /**
   * See if the current user (if any) can map LTI launch links to destinations.
   *
   * @todo add proper checks, currently this just checks if the user is logged in.
   */
  public static function user_can_map_lti_links() {
    global $wp;
    $switched = FALSE;
    if ( ! ( empty( $wp->query_vars['blog'] ) ) ){
      switch_to_blog( (int) $wp->query_vars['blog'] );
      $switched = TRUE;
    }

    if ( is_user_logged_in() ) {
      $current_user = wp_get_current_user();
      if ( $current_user->has_cap(WISCPB_LTI_CAP_LINK_LTI) ) {
        if ( $switched ) {
          restore_current_blog();
        }
        return TRUE;
      }
    }
    if ( $switched ) {
      restore_current_blog();
    }
    return FALSE;
  }

  /**
   * Create a database table for storing LTI maps, this is a global table.
   */
  public static function create_db_table() {
    $table_name = WISCPB_LTI_TABLE;

    $sql = "CREATE TABLE $table_name (
      ID mediumint(9) NOT NULL AUTO_INCREMENT,
      resource_link_id TINYTEXT,
      target_action TINYTEXT,
      user_id mediumint(9),
      blog_id mediumint(9),
      PRIMARY KEY  (id),
      UNIQUE KEY resource_link_id (resource_link_id(32))
    );";

    require_once( ABSPATH . 'wp-admin/includes/upgrade.php');
    dbDelta( $sql );


    $outcome_table_name = WISC_OUTCOMES_TABLE;
    $outcomesql = "CREATE TABLE $outcome_table_name (
      ID mediumint(9) NOT NULL AUTO_INCREMENT,
      outcome_service_url LONGTEXT,
      outcome_source_id LONGTEXT,
      page_id mediumint(9),
      user_id mediumint(9),
      blog_id mediumint(9),
      PRIMARY KEY  (id),
      UNIQUE KEY outcome_element (page_id, user_id, blog_id)
    );";

    dbDelta($outcomesql);

    switch_to_blog(1);
    update_option( 'wiscpb_lti_db_version', WISCPB_LTI_DB_VERSION );
    restore_current_blog();
  }

  /**
   * Remove database table.
   */
  public static function remove_db_table() {
    global $wpdb;
    $table_name = WISCPB_LTI_TABLE;
    $wpdb->query("DROP TABLE IF EXISTS $table_name");
    delete_option('wiscpb_lti_db_version');
  }

  public static function save_outcome_info($url, $page, $user, $blogid, $sourceid){
      global $wpdb;
      if (is_null($blogid)){
          $blogid = -1;
      }
      $table = WISC_OUTCOMES_TABLE;
      $values = array(
          'outcome_service_url' => $url,
          'page_id' => $page,
          'outcome_source_id' => $sourceid,
          'user_id' => $user,
          'blog_id' => $blogid,
      );

      $wpdb->replace($table, $values);

  }

  public static function sendGrade($grade, $userid, $page_id, $blog_id){
      global $wpdb;
      $table_name = WISC_OUTCOMES_TABLE;
      $sql = $wpdb->prepare("SELECT * FROM $table_name WHERE page_id  = %s AND user_id = %s AND blog_id = %s", $page_id, $userid, $blog_id);

      $outcome_info = $wpdb->get_row( $sql );
      if (is_null($outcome_info->outcome_source_id)) return;
      self::sendPOXGrade($grade, $outcome_info->outcome_source_id, $outcome_info->outcome_service_url);
  }

  public static function sendPOXGrade($grade, $sourceid, $outcome_url){
      global $wpdb;

      $content_type = "application/xml";
      $sourceid = htmlspecialchars($sourceid);

      $postBody = str_replace(
          array('SOURCEDID', 'GRADE', 'OPERATION','MESSAGE'),
          array($sourceid, $grade.'', 'replaceResultRequest', uniqid()),
          self::getPOXGradeRequest());

      $table_name = $wpdb->base_prefix . "postmeta";
      $sql = $wpdb->prepare("SELECT * FROM $table_name WHERE meta_key = %s", '_lti_consumer_key');
      $consumer_key = $wpdb->get_row($sql);

      $sql = $wpdb->prepare("SELECT * FROM $table_name WHERE meta_key = %s", '_lti_consumer_secret');
      $consumer_secret = $wpdb->get_row($sql);


      $response = self::sendOAuthBody("POST", $outcome_url, $consumer_key->meta_value, $consumer_secret->meta_value,
          $content_type, $postBody);

  }

  public static function getPOXGradeRequest() {
        return '<?xml version = "1.0" encoding = "UTF-8"?>
    <imsx_POXEnvelopeRequest xmlns = "http://www.imsglobal.org/services/ltiv1p1/xsd/imsoms_v1p0">
      <imsx_POXHeader>
        <imsx_POXRequestHeaderInfo>
          <imsx_version>V1.0</imsx_version>
          <imsx_messageIdentifier>MESSAGE</imsx_messageIdentifier>
        </imsx_POXRequestHeaderInfo>
      </imsx_POXHeader>
      <imsx_POXBody>
        <OPERATION>
          <resultRecord>
            <sourcedGUID>
              <sourcedId>SOURCEDID</sourcedId>
            </sourcedGUID>
            <result>
              <resultScore>
                <language>en-us</language>
                <textString>GRADE</textString>
              </resultScore>
            </result>
          </resultRecord>
        </OPERATION>
      </imsx_POXBody>
    </imsx_POXEnvelopeRequest>';
    }

  public static function sendOAuthBody($method, $endpoint, $oauth_consumer_key, $oauth_consumer_secret,
                                         $content_type, $body, $more_headers=false, $signature=false)
    {
        $files = glob( __DIR__ . '/OAuth/*.php' );

        foreach ($files as $file) {
            require_once($file);
        }
        require_once( __DIR__ . '/../wiscpb-lti/Net.php' );

        $hmac_method = new OAuthSignatureMethod_HMAC_SHA1();
        $hash = base64_encode(sha1($body, TRUE));

        $parms = array('oauth_body_hash' => $hash);
        $test_token = '';
        $test_consumer = new OAuthConsumer($oauth_consumer_key, $oauth_consumer_secret, NULL);
        $acc_req = OAuthRequest::from_consumer_and_token($test_consumer, $test_token, $method, $endpoint, $parms);
        $acc_req->sign_request($hmac_method, $test_consumer, $test_token);
        // Pass this back up "out of band" for debugging
        global $LastOAuthBodyBaseString;
        $LastOAuthBodyBaseString = $acc_req->get_signature_base_string();
        $header = $acc_req->to_header();
        $header = $header . "\r\nContent-Type: " . $content_type . "\r\n";
        if ( $more_headers === false ) $more_headers = array();
        foreach ($more_headers as $more ) {
            $header = $header . $more . "\r\n";
        }
        return Net::doBody($endpoint, $method, $body,$header);
    }

  public static function write_log( $log ) {
    if ( true === WP_DEBUG && true === WISCPB_LTI::DEBUG_LOG ) {
      if ( is_array( $log ) || is_object( $log ) ) {
        error_log( print_r( $log, true ) );
      } else {
        error_log( $log );
      }
    }
  }

}
