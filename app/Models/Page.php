<?php

namespace Choose\Models;

use Illuminate\Database\Eloquent\Model;

class Page extends Model {

    protected $fillable = [
        'page_slug',
        'template',
        'options',
        'content',
        'order',
    ];


}
