<?php namespace Choose\Http\Controllers;

use Choose\Models\Page;
use Illuminate\Support\Facades\Input;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Facades\Redirect;

class WelcomeController extends Controller
{

    protected $template = 'choose2015';

    /*
    |--------------------------------------------------------------------------
    | Welcome Controller
    |--------------------------------------------------------------------------
    |
    | This controller renders the "marketing page" for the application and
    | is configured to only allow guests. Like most of the other sample
    | controllers, you are free to modify or remove it as you desire.
    |
    */

    /**
     * Create a new controller instance.
     *
     * @return void
     */
    public function __construct()
    {
        $this->middleware('guest');
    }

    /**
     * Show the application welcome screen to the user.
     *
     * @return Response
     */
    public function index($page=null)
    {

        $pages = [];

        $pageModel = Page::all()->each(function($p) use(&$pages) {
            $singlePage = [
                'section' => $p->template,
                'options' => array_merge([
                    'sectionId' => $p->page_slug,
                ], is_array(json_decode($p->options, true)) ? json_decode($p->options, true) : []),
                'content' => is_array(json_decode($p->content, true)) ? json_decode($p->content, true) : []
            ];
            $pages[] = $singlePage;
        });

        \View::share('template', $this->template);

        return view('welcome', [ 'currentPage' => $page, 'pages' => $pages ]);
    }

    public function sendForm()
    {
        $details = Input::all();


        Mail::send('email.contactform', [
            'name' => $details['name'],
            'email' => $details['email'],
            'telephone' => $details['telephone'],
            'messageContent' => $details['message'],
        ], function($m) {
            $m->to('data.lovers@chooseleads.co.uk', 'ChooseLeads')->subject('Website Contact Form');
        });


        return Redirect::to('/');
    }

}
